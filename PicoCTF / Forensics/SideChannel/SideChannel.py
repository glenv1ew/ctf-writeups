import time
import subprocess
pin=""
charset="1234567890"

for i in range(8):
 bestc=None
 bestt=0
 for c in charset:
  test=pin+c+"0"*(7-i)
  start_time=time.perf_counter()
  subprocess.run(["./pin_checker"], input=test+"\n",stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
  script_time=time.perf_counter()-start_time
  if script_time > bestt:
   bestt=script_time
   bestc=c
 pin+=bestc
 print("\n Found ", pin)
print("\n Final pin:", pin)
