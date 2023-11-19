#include <Wire.h>

long miliCurrent = 0; 
int nMeas = 1;
unsigned long tim;
#define N_SAMPLE (2048*10) //2048ms
short rawVoltage[N_SAMPLE];
unsigned int deltaTime_us[N_SAMPLE];
int samplesTaken = 0;
int nsampleToSweep = 1000;
int milliOhmRegBank;

void ShutDownRegBank()
{
  digitalWrite(3, HIGH);
  digitalWrite(4, HIGH);
  digitalWrite(5, HIGH);
  digitalWrite(6, HIGH);
}

void ActivateRegBank(int milliOhm)
{
  ShutDownRegBank();
  switch(milliOhm){
    case 82: 
      digitalWrite(3, HIGH); 
      digitalWrite(4, HIGH); 
      break;
    case 100: digitalWrite(3, HIGH); break;
    case 470: digitalWrite(4, HIGH); break;
    case 3333:
      digitalWrite(5, HIGH); 
      digitalWrite(6, HIGH); 
      break;
    case 5000: digitalWrite(5, HIGH); break;
    case 10000: digitalWrite(6, HIGH); break;
    default: 
      break;
  }
  milliOhmRegBank = milliOhm;
}


void setup() {
  // put your setup code here, to run once:
  pinMode(3, OUTPUT); //0.1ohm
  digitalWrite(3, HIGH); // active low
  pinMode(4, OUTPUT); // 0.47ohm
  digitalWrite(4, HIGH); // active low
  pinMode(5, OUTPUT); // 5ohm
  digitalWrite(5, HIGH); // active low
  pinMode(6, OUTPUT); // 10ohm
  digitalWrite(6, HIGH); // active low

  pinMode(7, OUTPUT); // Analog input0 relay
  digitalWrite(7, HIGH); // active high

  Serial.begin(115200 );
  Serial.println("hello");
  //analogReference (DEFAULT); //5V
  analogReadResolution(12);
  
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
  Serial.println("[I] Battery health analyzer booted up.");
  Serial.print("sizeof(int):");
  Serial.println(sizeof(int));
  //digitalWrite(3, LOW);
  //digitalWrite(4, LOW);
  digitalWrite(5, LOW);
   //digitalWrite(6, LOW);
}

long AdcRawToVoltage(long raw)
{
  //Vref = 3.0V
  return raw * 30 * 2 / (4096/100); //ADC入力での電圧は抵抗分圧で1/2
}

void PrintVoltage(int raw)
{
  long v = AdcRawToVoltage(raw);
  Serial.print(tim);
  Serial.print(", ");
  Serial.print(raw);
  Serial.print(", ");
  Serial.println(v);
}

void PrintResult()
{
  int i;
  long v;

  for(i = 0; i < nsampleToSweep; i++){
    Serial.print(deltaTime_us[i]);
    Serial.print(", ");
    Serial.print(rawVoltage[i]);
    Serial.print(", ");
    v = AdcRawToVoltage(rawVoltage[i]);
    Serial.println(v);
 }
}

void DoSweep()
{
  int i;
  unsigned int timeBeginUs = micros();
  unsigned int nextTick = timeBeginUs;
  unsigned int tickNow = timeBeginUs;

  for(i = 0; i < nsampleToSweep; i++){
    while( tickNow < nextTick){
      tickNow = micros();
    }
    nextTick = tickNow + 25;
    rawVoltage[samplesTaken] = analogRead(A0);
    deltaTime_us[samplesTaken] = tickNow - timeBeginUs;
    samplesTaken++;
  }
}

void loop() {
  // put your main code here, to run repeatedly:
  tim = millis();
  long v,ref;

  for(;;){ //wait for next 1ms period. 実際は1ループ1.032ms程度になる
    if( tim != millis() ){
      break; 
    }
  }
  miliCurrent++;
/*
  if(0 < nMeas){
    DoSweep();
    ShutDownRegBank();
    PrintResult();
    nMeas--;
  }
*/
  if(0 < nMeas ){
    if(miliCurrent < 1000){
      if( 0 == (miliCurrent & 0x1F ) ){
        ref = analogRead(A0);
        PrintVoltage(ref);
      }
    }
    else{
        //ShutDownRegBank();
        nMeas--;
    }
  }
  else{
    if(0 == (miliCurrent & 0x7FF)){
        ref = analogRead(A0);
        PrintVoltage(ref);
    }
  }
}

float calcTemp(int raw) 
{
  float refV = 3200; //Reference voltage [mV]
  float R = 20000; //分圧抵抗
  float RT25 = 20000; //25度のときのサーミスタ抵抗値
  float B = 3950;
  float rV,ntcR,ntcV,circuitI;
  float tempK; //ケルビン気温
  
  rV = raw * refV / 1024; //分圧抵抗の電圧降下
  ntcV = refV - rV;
  circuitI = rV / R; //回路電流
  ntcR = ntcV / circuitI;
 // Serial.println( ntcR); 

  tempK=1000/(1/(0.001*298)+log(ntcR/RT25)*1000/B);  //298K=摂氏25度
  
  return (tempK - 273);
}
