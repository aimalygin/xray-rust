// Diagnostic control using the pinned Go peer's SS2022 library.
package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "strconv"
 "strings"
 "net"
 "os"
 "time"
 ss "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
 M "github.com/sagernet/sing/common/metadata"
)

type Fixture struct { Cases []struct { ConfigJSON string }; UDPPort int }
type Config struct { Outbounds []struct { Settings struct { Address string; Port int; Method string; Password string } } }
type ObservedConn struct { net.Conn; Sent, Received []int }
func (c *ObservedConn) Write(p []byte) (int,error) { n,e:=c.Conn.Write(p);c.Sent=append(c.Sent,n);return n,e }
func (c *ObservedConn) Read(p []byte) (int,error) { n,e:=c.Conn.Read(p);c.Received=append(c.Received,n);return n,e }
func main() {
 raw,e:=os.ReadFile(os.Args[1]);if e!=nil { panic("fixture unavailable") }
 var f Fixture;if json.Unmarshal(raw,&f)!=nil || len(f.Cases)!=1 { panic("invalid fixture") }
 var cfg Config;if json.Unmarshal([]byte(f.Cases[0].ConfigJSON),&cfg)!=nil { panic("invalid config") }
 s:=cfg.Outbounds[0].Settings
 method,e:=ss.NewWithPassword(s.Method,s.Password,time.Now);if e!=nil { panic("invalid method") }
 sizes:=[]int{32,1200,1300,1320,1340,1350,1360,1372,1392,1420,1450}
 if len(os.Args)>2 { sizes=nil;for _,raw:=range strings.Split(os.Args[2],","){n,e:=strconv.Atoi(raw);if e!=nil || n<1 || n>8192{panic("invalid size")};sizes=append(sizes,n)} }
 encoder:=json.NewEncoder(os.Stdout)
 for _,host:=range []string{"198.51.100.7","2001:db8::7"} {
  for _,size:=range sizes {
   for repeat:=0;repeat<2;repeat++ {
   started:=time.Now()
   rawConn,e:=net.DialTimeout("udp",net.JoinHostPort(s.Address,fmt.Sprint(s.Port)),3*time.Second)
   if e!=nil { panic("carrier dial failed") }
   observed:=&ObservedConn{Conn:rawConn}; c:=method.DialPacketConn(observed)
   destination:=M.ParseSocksaddr(net.JoinHostPort(host,fmt.Sprint(f.UDPPort)))
   payload:=bytes.Repeat([]byte{0x6b},size)
   _=c.SetDeadline(time.Now().Add(1500*time.Millisecond))
   _,sendErr:=c.WriteTo(payload,destination)
   buf:=make([]byte,9000);n,source,recvErr:=c.ReadFrom(buf)
   row:=map[string]any{"unix_start":float64(started.UnixNano())/1e9,"seconds":time.Since(started).Seconds(),"local_port":rawConn.LocalAddr().(*net.UDPAddr).Port,"host":host,"payload_bytes":size,"repeat":repeat,"sent_wire_bytes":observed.Sent,"received_wire_bytes":observed.Received,"passed":sendErr==nil && recvErr==nil && bytes.Equal(payload,buf[:n])}
   if source!=nil { row["reply_source"]=source.String();row["source_matches"]=source.String()==destination.String() }
   if recvErr!=nil { if ne,ok:=recvErr.(net.Error);ok && ne.Timeout() { row["error"]="timeout" } else { row["error"]="receive_error" } }
   encoder.Encode(row);c.Close()
   }
  }
 }
}
