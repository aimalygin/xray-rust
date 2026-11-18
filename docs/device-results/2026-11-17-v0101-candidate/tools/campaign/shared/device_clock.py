import time
import drive as d

def calibrate():
    samples=[]
    for _ in range(5):
        before=time.time()
        phone=float(d.shell('date','+%s.%N').strip())
        after=time.time()
        samples.append({'offsetSeconds':phone-(before+after)/2,'uncertaintySeconds':(after-before)/2,'hostBefore':before,'hostAfter':after,'phone':phone})
    best=min(samples,key=lambda s:s['uncertaintySeconds'])
    assert best['uncertaintySeconds']<0.15,best
    d.emit('device-clock-calibration',selected=best,samples=samples)
    return best
