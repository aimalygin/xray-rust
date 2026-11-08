// Drives Xray-core's BBR sender (transport/internet/hysteria/congestion/bbr)
// over simulated paths and records every call it receives, with a digest of
// its whole state after each congestion event and datagram size change. The
// Rust port replays the calls and must reach the same state at every step:
// tests/fixtures/bbr/xray-bbr-trace.json.zst holds this program's output,
// compressed with zstd.
//
// A path has the sender paced by its own pacer, a bottleneck with a drop-tail
// queue, random loss, a receiver that acknowledges every few packets or after
// a delay, and quic-go's loss detection: the packet threshold of three, the
// time threshold of 9/8 RTT and probe timeouts. Phases change the rate, the
// loss, how much the application has to send, the datagram size, and send
// ACK-only packets, some with nothing in flight.
//
// Everything is deterministic: paths draw from seeded PCG generators, and the
// sender's PROBE_BW gain-cycle draws come from math/rand's global source,
// seeded per run (the go:debug line makes rand.Seed effective), so a fresh
// run matches the fixture byte for byte. Each run lists the draws that
// source yields, in order, for the port to take as its own.
//
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json.

//go:debug randseednop=0
package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	randv2 "math/rand/v2"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
)

// quic-go's monotonic clock starts an hour in the past; steps record the
// time since then.
const clockStart = monotime.Time(time.Hour)

// The surface of NewBbrSender's unexported type.
type sender interface {
	congestion.CongestionControlEx
	PacingRate() bbr.Bandwidth
}

// rttStats is quic-go's RTTStats as far as the sender reads it, the smallest
// positive raw sample, plus a smoothed RTT for the path's timers.
type rttStats struct {
	min, latest, smoothed, meanDeviation time.Duration
}

func (r *rttStats) MinRTT() time.Duration          { return r.min }
func (r *rttStats) LatestRTT() time.Duration       { return r.latest }
func (r *rttStats) SmoothedRTT() time.Duration     { return r.smoothed }
func (r *rttStats) MeanDeviation() time.Duration   { return r.meanDeviation }
func (r *rttStats) MaxAckDelay() time.Duration     { return 25 * time.Millisecond }
func (r *rttStats) PTO(bool) time.Duration         { return r.pto() }
func (r *rttStats) UpdateRTT(_, _ time.Duration)   {}
func (r *rttStats) SetMaxAckDelay(time.Duration)   {}
func (r *rttStats) SetInitialRTT(time.Duration)    {}

func (r *rttStats) sample(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	if r.min == 0 || rtt < r.min {
		r.min = rtt
	}
	r.latest = rtt
	if r.smoothed == 0 {
		r.smoothed = rtt
		r.meanDeviation = rtt / 2
		return
	}
	deviation := r.smoothed - rtt
	if deviation < 0 {
		deviation = -deviation
	}
	r.meanDeviation = (3*r.meanDeviation + deviation) / 4
	r.smoothed = (7*r.smoothed + rtt) / 8
}

func (r *rttStats) pto() time.Duration {
	if r.smoothed == 0 {
		return time.Second
	}
	return r.smoothed + max(4*r.meanDeviation, time.Millisecond) + 25*time.Millisecond
}

type packet struct {
	number  int64
	size    int64
	sent    monotime.Time
	arrives monotime.Time
}

type ackFrame struct {
	at      monotime.Time
	numbers []int64
}

// A phase changes the path or the application from `at` on. Negative
// values keep the current setting.
type phase struct {
	at time.Duration
	// Bottleneck rate, bytes per second.
	rate float64
	loss float64
	// Bytes per second the application has to send; zero is idle, and
	// math.Inf(1) unlimited.
	app float64
	// Raise the datagram size to this, if positive.
	datagram int64
	// An ACK-only packet this often; zero sends none.
	ackOnly time.Duration
}

type scenario struct {
	name     string
	seed     uint64
	duration time.Duration
	rtt      time.Duration
	queue    int64
	ackEvery int
	ackDelay time.Duration
	datagram int64
	phases   []phase
}

type run struct {
	Name     string  `json:"name"`
	Profile  string  `json:"profile"`
	Datagram int64   `json:"datagram"`
	Draws    []int32 `json:"draws"`
	Steps    [][]any `json:"steps"`
}

type trace struct {
	Source string `json:"source"`
	Steps  string `json:"steps"`
	State  string `json:"state"`
	Runs   []run  `json:"runs"`
}

const stepFormat = `["s", time, bytesInFlight, packetNumber, bytes, retransmittable] OnPacketSent; ` +
	`["r", rtt] an RTT sample before the next event; ` +
	`["e", priorInFlight, time, [[packetNumber, bytesAcked]...], [[packetNumber, bytesLost]...], digest(, state)] OnCongestionEventEx; ` +
	`["m", size, digest(, state)] SetMaxDatagramSize. ` +
	`Times are nanoseconds after quic-go's clock start of one hour; ` +
	`the state, every 16th snapshot, lists the digested values`

// stateFields names, in order, the values each digest covers.
var stateFields = []string{
	"mode", "recoveryState", "cycleCurrentOffset", "roundTripCount", "minRtt", "minRttTimestamp",
	"congestionWindow", "recoveryWindow", "GetCongestionWindow", "pacingRate", "PacingRate",
	"pacingGain(bits)", "congestionWindowGain(bits)", "isAtFullBandwidth", "roundsWithoutBandwidthGain",
	"bandwidthAtLastRound", "maxBandwidth", "exitProbeRttAt", "probeRttRoundPassed",
	"lastSampleIsAppLimited", "hasNoAppLimitedSample", "endRecoveryAt", "currentRoundTripEnd",
	"numLossEventsInRound", "bytesLostInRound", "detectOvershooting",
	"bytesLostWhileDetectingOvershooting", "bytesInFlight", "exitingQuiescence", "lastSentPacket",
	"maxDatagramSize", "initialCongestionWindow", "minCongestionWindow", "maxCongestionWindow",
	"cwndToCalculateMinPacingRate", "lastCycleStart",
	"sampler.totalBytesSent", "sampler.totalBytesAcked", "sampler.totalBytesLost",
	"sampler.totalBytesSentAtLastAckedPacket", "sampler.lastAckedPacketSentTime",
	"sampler.lastAckedPacketAckTime", "sampler.lastSentPacket", "sampler.isAppLimited",
	"sampler.endOfAppLimitedPhase", "sampler.totalBytesAckedAfterLastAckEvent",
	"sampler.connectionStateMap.present", "sampler.connectionStateMap.firstPacket",
	"sampler.a0Candidates.len", "ackHeight.aggregationEpochStartTime", "ackHeight.aggregationEpochBytes",
	"ackHeight.best", "ackHeight.secondBest", "ackHeight.thirdBest",
}

func boolean(v reflect.Value) int64 {
	if v.Bool() {
		return 1
	}
	return 0
}

// ringLen is RingBuffer.Len.
func ringLen(ring reflect.Value) int64 {
	size := int64(ring.FieldByName("ring").Len())
	if ring.FieldByName("full").Bool() {
		return size
	}
	head := ring.FieldByName("headPos").Int()
	tail := ring.FieldByName("tailPos").Int()
	if tail >= head {
		return tail - head
	}
	return tail - head + size
}

// state reads the sender, unexported fields included, in stateFields order.
func state(s sender) []any {
	v := reflect.ValueOf(s).Elem()
	f := v.FieldByName
	sampler := f("sampler").Elem()
	g := sampler.FieldByName
	tracker := g("maxAckHeightTracker").Elem()
	heights := tracker.FieldByName("maxAckHeightFilter").Elem().FieldByName("estimates")
	queue := g("connectionStateMap").Elem()
	height := func(i int) int64 { return heights.Index(i).FieldByName("sample").FieldByName("extraAcked").Int() }
	return []any{
		f("mode").Int(), f("recoveryState").Int(), f("cycleCurrentOffset").Int(),
		f("roundTripCount").Uint(), f("minRtt").Int(), f("minRttTimestamp").Int(),
		f("congestionWindow").Int(), f("recoveryWindow").Int(), int64(s.GetCongestionWindow()),
		f("pacingRate").Uint(), uint64(s.PacingRate()),
		math.Float64bits(f("pacingGain").Float()), math.Float64bits(f("congestionWindowGain").Float()),
		boolean(f("isAtFullBandwidth")), f("roundsWithoutBandwidthGain").Int(),
		f("bandwidthAtLastRound").Uint(),
		f("maxBandwidth").Elem().FieldByName("estimates").Index(0).FieldByName("sample").Uint(),
		f("exitProbeRttAt").Int(), boolean(f("probeRttRoundPassed")),
		boolean(f("lastSampleIsAppLimited")), boolean(f("hasNoAppLimitedSample")),
		f("endRecoveryAt").Int(), f("currentRoundTripEnd").Int(),
		f("numLossEventsInRound").Uint(), f("bytesLostInRound").Int(), boolean(f("detectOvershooting")),
		f("bytesLostWhileDetectingOvershooting").Int(), f("bytesInFlight").Int(),
		boolean(f("exitingQuiescence")), f("lastSentPacket").Int(),
		f("maxDatagramSize").Int(), f("initialCongestionWindow").Int(), f("minCongestionWindow").Int(),
		f("maxCongestionWindow").Int(), f("cwndToCalculateMinPacingRate").Int(), f("lastCycleStart").Int(),
		g("totalBytesSent").Int(), g("totalBytesAcked").Int(), g("totalBytesLost").Int(),
		g("totalBytesSentAtLastAckedPacket").Int(), g("lastAckedPacketSentTime").Int(),
		g("lastAckedPacketAckTime").Int(), g("lastSentPacket").Int(), boolean(g("isAppLimited")),
		g("endOfAppLimitedPhase").Int(), g("totalBytesAckedAfterLastAckEvent").Int(),
		queue.FieldByName("numberOfPresentEntries").Int(), queue.FieldByName("firstPacket").Int(),
		ringLen(g("a0Candidates")),
		tracker.FieldByName("aggregationEpochStartTime").Int(), tracker.FieldByName("aggregationEpochBytes").Int(),
		height(0), height(1), height(2),
	}
}

// digest is FNV-1a 64 over the decimal values joined by commas.
func digest(values []any) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprint(value)
	}
	h := fnv.New64a()
	h.Write([]byte(strings.Join(parts, ",")))
	return strconv.FormatUint(h.Sum64(), 16)
}

type path struct {
	sc    scenario
	rng   *randv2.Rand
	s     sender
	stats *rttStats
	now   monotime.Time
	end   monotime.Time

	nextNumber int64
	inFlight   int64
	datagram   int64
	// Retransmittable packets neither acknowledged nor lost, in order.
	outstanding []*packet
	largest     int64

	rate     float64
	loss     float64
	linkFree monotime.Time
	// Delivered packets on their way to the receiver, in arrival order.
	transit []*packet
	// Received but not yet acknowledged, and when the delayed ACK is due.
	pending []int64
	ackDue  monotime.Time
	frames  []ackFrame

	app        float64
	budget     float64
	budgetTime monotime.Time
	ackOnly    time.Duration
	nextAckOff monotime.Time

	ptoAt     monotime.Time
	ptoCount  uint
	phase     int
	snapshots int
	steps     [][]any
}

func (p *path) elapsed() int64 { return int64(p.now - clockStart) }

func (p *path) snapshot(st []any) {
	values := state(p.s)
	st = append(st, digest(values))
	p.snapshots++
	if p.snapshots%16 == 0 {
		st = append(st, values)
	}
	p.steps = append(p.steps, st)
}

func (p *path) send(retransmittable bool) {
	number := p.nextNumber
	p.nextNumber++
	size := int64(50)
	if retransmittable {
		size = p.datagram
		p.inFlight += size
	}
	p.s.OnPacketSent(p.now, congestion.ByteCount(p.inFlight), congestion.PacketNumber(number),
		congestion.ByteCount(size), retransmittable)
	flag := 0
	if retransmittable {
		flag = 1
	}
	p.steps = append(p.steps, []any{"s", p.elapsed(), p.inFlight, number, size, flag})
	if !retransmittable {
		return
	}
	pk := &packet{number: number, size: size, sent: p.now}
	p.outstanding = append(p.outstanding, pk)
	if p.app != 0 && !math.IsInf(p.app, 1) {
		p.budget -= float64(size)
	}
	if p.ptoAt == 0 {
		p.ptoAt = p.now + monotime.Time(p.stats.pto())
	}
	start := max(p.linkFree, p.now)
	backlog := int64(float64(start-p.now) / 1e9 * p.rate)
	if backlog+size > p.sc.queue {
		return // tail drop
	}
	p.linkFree = start + monotime.Time(float64(size)/p.rate*1e9)
	if p.rng.Float64() < p.loss {
		return // lost past the bottleneck
	}
	pk.arrives = p.linkFree + monotime.Time(p.sc.rtt/2)
	p.transit = append(p.transit, pk)
}

func (p *path) refillBudget() {
	if math.IsInf(p.app, 1) || p.app == 0 {
		p.budgetTime = p.now
		return
	}
	p.budget = min(p.budget+p.app*float64(p.now-p.budgetTime)/1e9, float64(4*p.datagram))
	p.budgetTime = p.now
}

func (p *path) hasData() bool {
	return math.IsInf(p.app, 1) || (p.app > 0 && p.budget >= float64(p.datagram))
}

// sendAt is when the sender may send its next data packet, or 0.
func (p *path) sendAt() monotime.Time {
	if !p.s.CanSend(congestion.ByteCount(p.inFlight)) {
		return 0
	}
	ready := p.now
	if !p.hasData() {
		if p.app == 0 || math.IsInf(p.app, 1) {
			return 0
		}
		ready = p.now + monotime.Time((float64(p.datagram)-p.budget)/p.app*1e9) + 1
	}
	if p.s.HasPacingBudget(ready) {
		return ready
	}
	return max(ready, p.s.TimeUntilSend(congestion.ByteCount(p.inFlight)))
}

func (p *path) lossDelay() time.Duration {
	delay := time.Duration(9.0 / 8.0 * float64(max(p.stats.latest, p.stats.smoothed)))
	return max(delay, time.Millisecond)
}

// lossAt is quic-go's loss timer: the earliest outstanding packet at or
// below the largest acknowledged, plus the loss delay.
func (p *path) lossAt() monotime.Time {
	for _, pk := range p.outstanding {
		if pk.number > p.largest {
			break
		}
		return pk.sent + monotime.Time(p.lossDelay())
	}
	return 0
}

// detect declares lost what quic-go would, after an ACK or on its timer.
func (p *path) detect() [][2]int64 {
	lost := [][2]int64{}
	deadline := p.now - monotime.Time(p.lossDelay())
	kept := p.outstanding[:0]
	for _, pk := range p.outstanding {
		if pk.number <= p.largest && (pk.sent <= deadline || p.largest-pk.number >= 3) {
			lost = append(lost, [2]int64{pk.number, pk.size})
			p.inFlight -= pk.size
			continue
		}
		kept = append(kept, pk)
	}
	p.outstanding = kept
	return lost
}

func lostInfo(lost [][2]int64) []congestion.LostPacketInfo {
	out := make([]congestion.LostPacketInfo, 0, len(lost))
	for _, l := range lost {
		out = append(out, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(l[0]), BytesLost: congestion.ByteCount(l[1])})
	}
	return out
}

func (p *path) onFrame(frame ackFrame) {
	prior := p.inFlight
	acked := [][2]int64{}
	var ackedInfo []congestion.AckedPacketInfo
	var largestSent monotime.Time
	largestNew := int64(-1)
	kept := p.outstanding[:0]
	wanted := map[int64]bool{}
	for _, number := range frame.numbers {
		wanted[number] = true
	}
	for _, pk := range p.outstanding {
		if !wanted[pk.number] {
			kept = append(kept, pk)
			continue
		}
		p.inFlight -= pk.size
		acked = append(acked, [2]int64{pk.number, pk.size})
		ackedInfo = append(ackedInfo, congestion.AckedPacketInfo{
			PacketNumber: congestion.PacketNumber(pk.number), BytesAcked: congestion.ByteCount(pk.size), ReceivedTime: p.now,
		})
		largestNew = pk.number
		largestSent = pk.sent
	}
	p.outstanding = kept
	if len(acked) == 0 {
		return
	}
	frameLargest := frame.numbers[len(frame.numbers)-1]
	p.largest = max(p.largest, frameLargest)
	if largestNew == frameLargest {
		sample := time.Duration(p.now - largestSent)
		p.stats.sample(sample)
		p.steps = append(p.steps, []any{"r", int64(sample)})
	}
	lost := p.detect()
	p.s.OnCongestionEventEx(congestion.ByteCount(prior), p.now, ackedInfo, lostInfo(lost))
	p.snapshot([]any{"e", prior, p.elapsed(), acked, lost})
	p.ptoCount = 0
	p.ptoAt = 0
	if p.inFlight > 0 {
		p.ptoAt = p.now + monotime.Time(p.stats.pto())
	}
}

func (p *path) onLossTimer() {
	prior := p.inFlight
	lost := p.detect()
	if len(lost) == 0 {
		return
	}
	p.s.OnCongestionEventEx(congestion.ByteCount(prior), p.now, nil, lostInfo(lost))
	p.snapshot([]any{"e", prior, p.elapsed(), [][2]int64{}, lost})
}

func (p *path) emitAck() {
	p.frames = append(p.frames, ackFrame{at: p.now + monotime.Time(p.sc.rtt/2), numbers: p.pending})
	p.pending = nil
	p.ackDue = 0
}

func (p *path) applyPhase(ph phase) {
	if ph.rate > 0 {
		p.rate = ph.rate
	}
	if ph.loss >= 0 {
		p.loss = ph.loss
	}
	if ph.app >= 0 {
		p.refillBudget()
		p.app = ph.app
		p.budget = 0
	}
	if ph.datagram > 0 {
		p.datagram = ph.datagram
		p.s.SetMaxDatagramSize(congestion.ByteCount(ph.datagram))
		p.snapshot([]any{"m", ph.datagram})
	}
	if ph.ackOnly >= 0 {
		p.ackOnly = ph.ackOnly
		p.nextAckOff = 0
		if ph.ackOnly > 0 {
			p.nextAckOff = p.now + monotime.Time(ph.ackOnly)
		}
	}
}

// next returns the earliest pending event's time and kind.
func (p *path) next() (monotime.Time, string) {
	best, kind := p.end, "end"
	consider := func(at monotime.Time, what string) {
		if at != 0 && at < best {
			best, kind = at, what
		}
	}
	if len(p.frames) > 0 {
		consider(p.frames[0].at, "frame")
	}
	if len(p.transit) > 0 {
		consider(p.transit[0].arrives, "arrive")
	}
	consider(p.ackDue, "ackDue")
	consider(p.lossAt(), "loss")
	if p.inFlight > 0 {
		consider(p.ptoAt, "pto")
	}
	if p.phase < len(p.sc.phases) {
		consider(clockStart+monotime.Time(p.sc.phases[p.phase].at), "phase")
	}
	consider(p.nextAckOff, "ackOnly")
	if at := p.sendAt(); at != 0 {
		consider(max(at, p.now), "send")
	}
	return best, kind
}

func simulate(sc scenario, profile bbr.Profile, gainSeed int64) run {
	rand.Seed(gainSeed)
	// The same sequence the sender will draw from the global source.
	shadow := rand.New(rand.NewSource(gainSeed))
	draws := make([]int32, 64)
	for i := range draws {
		draws[i] = shadow.Int31n(congestion.PacketsPerConnectionID)
	}
	s := bbr.NewBbrSender(bbr.DefaultClock{}, congestion.ByteCount(sc.datagram), profile)
	stats := &rttStats{}
	s.SetRTTStatsProvider(stats)
	p := &path{
		sc:       sc,
		rng:      randv2.New(randv2.NewPCG(sc.seed, uint64(gainSeed))),
		s:        s,
		stats:    stats,
		now:      clockStart,
		end:      clockStart + monotime.Time(sc.duration),
		datagram: sc.datagram,
		largest:  -1,
		app:      math.Inf(1),
	}
	for {
		at, kind := p.next()
		if kind == "end" {
			break
		}
		p.now = max(p.now, at)
		p.refillBudget()
		switch kind {
		case "frame":
			frame := p.frames[0]
			p.frames = p.frames[1:]
			p.onFrame(frame)
		case "arrive":
			pk := p.transit[0]
			p.transit = p.transit[1:]
			p.pending = append(p.pending, pk.number)
			if len(p.pending) >= sc.ackEvery {
				p.emitAck()
			} else if p.ackDue == 0 {
				p.ackDue = p.now + monotime.Time(sc.ackDelay)
			}
		case "ackDue":
			p.emitAck()
		case "loss":
			p.onLossTimer()
		case "pto":
			// A probe bypasses the window and the pacer.
			p.ptoCount++
			p.send(true)
			p.ptoAt = p.now + monotime.Time(p.stats.pto())<<min(p.ptoCount, 6)
		case "phase":
			p.applyPhase(sc.phases[p.phase])
			p.phase++
		case "ackOnly":
			p.send(false)
			p.nextAckOff = p.now + monotime.Time(p.ackOnly)
		case "send":
			p.send(true)
		}
	}
	return run{Name: sc.name, Profile: string(profile), Datagram: sc.datagram, Draws: draws, Steps: p.steps}
}

const ms = time.Millisecond

func keep() phase { return phase{rate: -1, loss: -1, app: -1, ackOnly: -1} }

func main() {
	if len(os.Args) != 2 {
		panic("usage: bbr-oracle out.json")
	}
	unlimited := math.Inf(1)
	scenarios := []scenario{
		{
			name: "shallow-queue", seed: 1, duration: 6 * time.Second, rtt: 60 * ms,
			queue: 12_000, ackEvery: 2, ackDelay: 25 * ms, datagram: 1280,
			phases: []phase{{rate: 160_000, loss: 0, app: unlimited, ackOnly: 0}},
		},
		{
			name: "random-loss", seed: 2, duration: 5 * time.Second, rtt: 40 * ms,
			queue: 60_000, ackEvery: 2, ackDelay: 25 * ms, datagram: 1280,
			phases: []phase{{rate: 120_000, loss: 0.03, app: unlimited, ackOnly: 0}},
		},
		{
			name: "deep-queue-probe-rtt", seed: 3, duration: 13 * time.Second, rtt: 80 * ms,
			queue: 200_000, ackEvery: 2, ackDelay: 25 * ms, datagram: 1280,
			phases: []phase{{rate: 64_000, loss: 0, app: unlimited, ackOnly: 0}},
		},
		{
			name: "idle-and-quiescence", seed: 4, duration: 29 * time.Second, rtt: 50 * ms,
			queue: 50_000, ackEvery: 2, ackDelay: 25 * ms, datagram: 1280,
			phases: []phase{
				{rate: 128_000, loss: 0, app: unlimited, ackOnly: 0},
				// Idle for 11.5 s, answering the peer with ACK-only packets.
				func() phase { ph := keep(); ph.at = 2 * time.Second; ph.app = 0; ph.ackOnly = 300 * ms; return ph }(),
				func() phase { ph := keep(); ph.at = 13500 * ms; ph.app = unlimited; ph.ackOnly = 0; return ph }(),
				// Idle again, silent.
				func() phase { ph := keep(); ph.at = 15500 * ms; ph.app = 0; return ph }(),
				func() phase { ph := keep(); ph.at = 27 * time.Second; ph.app = unlimited; return ph }(),
			},
		},
		{
			name: "rate-mtu-aggregation", seed: 5, duration: 7 * time.Second, rtt: 30 * ms,
			queue: 40_000, ackEvery: 4, ackDelay: 40 * ms, datagram: 1280,
			phases: []phase{
				{rate: 200_000, loss: 0, app: unlimited, ackOnly: 0},
				func() phase { ph := keep(); ph.at = 2 * time.Second; ph.rate = 80_000; return ph }(),
				func() phase { ph := keep(); ph.at = 3 * time.Second; ph.datagram = 1452; return ph }(),
				func() phase { ph := keep(); ph.at = 4 * time.Second; ph.rate = 300_000; ph.loss = 0.01; return ph }(),
				// Application-limited at a sixth of the rate, then free again.
				func() phase { ph := keep(); ph.at = 5 * time.Second; ph.app = 50_000; ph.ackOnly = 100 * ms; return ph }(),
				func() phase { ph := keep(); ph.at = 6 * time.Second; ph.app = unlimited; ph.ackOnly = 0; return ph }(),
			},
		},
	}
	out := trace{
		Source: "Xray-core v26.10.31 transport/internet/hysteria/congestion/bbr, driven by tools/bbr-oracle",
		Steps:  stepFormat,
		State:  strings.Join(stateFields, ","),
	}
	for i, profile := range []bbr.Profile{bbr.ProfileConservative, bbr.ProfileStandard, bbr.ProfileAggressive} {
		for j, sc := range scenarios {
			out.Runs = append(out.Runs, simulate(sc, profile, int64(100*i+j+1)))
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	// One run per line keeps the file diffable once decompressed.
	text := strings.Replace(string(encoded), `{"name"`, "\n{\"name\"", -1)
	if err := os.WriteFile(os.Args[1], []byte(text+"\n"), 0o644); err != nil {
		panic(err)
	}
}
