#include <Wire.h>
#include <I2CLiquidCrystal.h>

I2CLiquidCrystal lcd(20, (bool)false); //5V I/O
int miliCurrent = 0; 

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200 );
  Serial.println("hello");
 pinMode(5, OUTPUT);
 digitalWrite(5, LOW);
  analogReference (EXTERNAL);
  
  lcd.begin(16, 2);
  lcd.print("hello, world!");
}

int v,ref;
  
void loop() {
  // put your main code here, to run repeatedly:
  unsigned long tim = millis();

  
  for(;;){ //wait for next 1ms period. 実際は1ループ1.032ms程度になる
    if( tim != millis() ){
      break; 
    }
  }
  miliCurrent++;
  if( 0 == (miliCurrent & 0x3 ) ){

    ref *= 3;
    ref += analogRead(A6);
    ref /= 4;
    v *= 3;
    v += analogRead(A0); //NTC
    v /= 4;
  } 
  
  if( 0 == (miliCurrent & 0x1FF ) ){
    ref = analogRead(A6);
    v = analogRead(A0); //NTC
   
   Serial.print(ref);
    Serial.print(", ");
    Serial.print(v);
    Serial.print(", ");
    Serial.println(calcTemp(v));

    lcd.setCursor(0, 1);
    lcd.print(ref);
    lcd.print(", ");
    lcd.print(v);
    lcd.print(", ");
    lcd.println(calcTemp(v));
    

  }
  if( miliCurrent < 15000 ){
      digitalWrite(5, HIGH);
  }else if( miliCurrent < 20000 ){
      digitalWrite(5, LOW);
  }else{
    miliCurrent = 0;
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
