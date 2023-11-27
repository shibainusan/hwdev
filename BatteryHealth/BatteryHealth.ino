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
int availableOhmsRegBank[] = {82, 100, 470, 3333, 5000, 10000};
bool isShowUnit = true;
float sumWattHour = 0;
float sumMilliAmpHour = 0;

void ShutDownRegBank()
{
  digitalWrite(3, HIGH);
  digitalWrite(4, HIGH);
  digitalWrite(5, HIGH);
  digitalWrite(6, HIGH);
}

bool ActivateRegBank(int milliOhm)
{
  ShutDownRegBank();
  switch(milliOhm){
    case 82: 
      digitalWrite(3, LOW); 
      digitalWrite(4, LOW); 
      break;
    case 100: digitalWrite(3, LOW); break;
    case 470: digitalWrite(4, LOW); break;
    case 3333:
      digitalWrite(5, LOW); 
      digitalWrite(6, LOW); 
      break;
    case 5000: digitalWrite(5, LOW); break;
    case 10000: digitalWrite(6, LOW); break;
    default: 
      ShutDownRegBank();
      milliOhmRegBank = 999999;
      return false;
      break;
  }
  milliOhmRegBank = milliOhm;
  return true;
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

  ActivateRegBank(470);
}

float AdcRawToVoltage(long raw)
{
  //Vref = 3.0V
  return raw * 3.0 * 2.0 / 4096; //ADC入力での電圧は抵抗分圧で1/2
}

void PrintVoltage()
{
  int raw = analogRead(A0);
  float v = AdcRawToVoltage(raw);
  Serial.print(miliCurrent);
  if(isShowUnit){ Serial.print("ms"); };
  Serial.print(", ");
  //Serial.print(raw);
  //Serial.print(", ");
  Serial.print(v);
  if(isShowUnit){ Serial.print("V"); };
  Serial.print(", ");
  float i = v / (milliOhmRegBank/ 1000.0);
  Serial.print(i);
  if(isShowUnit){ Serial.print("A"); };
  Serial.print(", ");
  sumMilliAmpHour += (i*1000/3600);
  Serial.print(sumMilliAmpHour);
  if(isShowUnit){ Serial.print("mAh"); };
  Serial.print(", ");

  float w = i*v;
  Serial.print(w);
  if(isShowUnit){ Serial.print("W"); };
  Serial.print(", ");
  sumWattHour += (w/3600);
  Serial.print(sumWattHour);
  if(isShowUnit){ Serial.print("Wh"); };
  Serial.print(", ");

  float t1,t2;
  raw = analogRead(A1);
  t1 = calcTemp(raw);
  raw = analogRead(A2);
  t2 = calcTemp(raw);
  Serial.print(t1);
  if(isShowUnit){ Serial.print("degC_BATT"); };
  Serial.print(", ");
  Serial.print(t2);
  if(isShowUnit){ Serial.print("degC_RES"); };
  Serial.print(", ");
  //Serial.print(raw);

  Serial.print(milliOhmRegBank);
  if(isShowUnit){ Serial.print("mOhm"); };
  Serial.print(", ");

  Serial.println("");
}

void PrintResult()
{
  int i;
  float v;

  for(i = 0; i < nsampleToSweep; i++){
    Serial.print(deltaTime_us[i]);
    Serial.print(", ");
    //Serial.print(rawVoltage[i]);
    //Serial.print(", ");
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

void OnSingleLine(char *line)
{
  String s;
  Serial.print("[");
  Serial.print(line);
  Serial.print("] ");
  char *cmd = strtok(line, " \t") ;
  if( NULL == cmd){
    return;
  }
  char *arg = strtok(NULL, " \t") ;

  if( 0 == strcasecmp(cmd, "?" ) ){
    Serial.println( "OK, available commands: q, sel1a, sel1b, sel2a, sel2b, sel3a, sel3b, sel4a, sel4b" );

  }else if( 0 == strcasecmp(cmd, "q" ) ){
    Serial.print( "OK, " );
  
  }else if( 0 == strcasecmp(cmd, "r" ) ){
    if( NULL == arg ){
      Serial.print( "OK, " );
      Serial.print(milliOhmRegBank);
      Serial.println(" milliOhm");
    }
    else{
      int ohm = atoi(arg);
      if(ActivateRegBank(ohm)){
        Serial.print( "OK, " );
        Serial.println("");
      }
      else{
        Serial.print( "FAILED, unavailable value." );
        Serial.println("");
      }
    }
   
  }else{
    Serial.println( "ERROR, Unknown command." );
  }
}

static char serialReadBuf[64];
static int serialReadPos = 0;

int FeedChar(int c)
{
  if( 0x0D == c || 0x0A == c ){ //is it CR or LF?
    if( 0 != serialReadPos ){
      serialReadBuf[serialReadPos] = '\0';
      OnSingleLine(serialReadBuf);
      serialReadPos = 0;
      return 1;
    }
    return 0;
  }
  //put the char into the buffer
  serialReadBuf[serialReadPos] = c;
  serialReadPos++;
  if( sizeof(serialReadBuf) <= serialReadPos ){
    //rewind the buffer when overrun
    serialReadPos = 0;
    serialReadBuf[serialReadPos] = '\0';
  }
  
  return 0;
}

void loop() {
  // put your main code here, to run repeatedly:
  tim = millis();

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
        //PrintVoltage();
      }
    }
    else{
        //ShutDownRegBank();
        nMeas--;
    }
  }
  else{
    if(0 == (miliCurrent % 1000)){
        PrintVoltage();
    }
  }
  if (0 < Serial.available() ) {
    FeedChar( Serial.read() );
  }
}

float calcTemp(int raw) 
{
  //NXFT15XH103FA2B050
  float refV = 3000; //Reference voltage [mV]
  float R = 10000; //分圧抵抗
  float RT25 = 10000; //25度のときのサーミスタ抵抗値
  float B = 3380;
  float rV,ntcR,ntcV,circuitI;
  float tempK; //ケルビン気温
  
  ntcV = raw * refV / 4096; //分圧抵抗の電圧降下
  rV = refV - ntcV;
  circuitI = rV / R; //回路電流
  ntcR = ntcV / circuitI;
  //char buf[256];
  //sprintf(buf, "%f, %f, %f, %f", ntcV, rV, circuitI, ntcR);
  //Serial.println(buf); 

  //tempK=1000/(1/(0.001*298)+log(ntcR/RT25)*1000/B);  //298K=摂氏25度
  tempK = 1/(1/B * log(ntcR/RT25)+ 1/298.15);
  
  return (tempK - 273);
}
