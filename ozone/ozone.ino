
/*
  Blink
  Turns on an LED on for one second, then off for one second, repeatedly.

  Most Arduinos have an on-board LED you can control. On the Uno and
  Leonardo, it is attached to digital pin 13. If you're unsure what
  pin the on-board LED is connected to on your Arduino model, check
  the documentation at http://www.arduino.cc

  This example code is in the public domain.

  modified 8 May 2014
  by Scott Fitzgerald
 */
#include <EEPROM.h>

int statDown = 999;
int statUp = 999;
int prevDown = 888;
int prevUp = 888;

#ifdef ARDUINO_AVR_UNO
int pinLED = 2;
int pinUpBtn = 3;
int pinDownBtn = 4;
int pinDebug = 5;
#else
int pinLED = 1;
int pinUpBtn = 0;
int pinDownBtn = 2;
int pinDebug = 4;
#endif



int onDuration = 0; //ON区間長の秒数
int offDuration = 0;//OFF区間長の秒数
int secCurrent = 0; //ON区間先頭からの経過秒数
int miliCurrent = 0; //１秒で１周するミリ秒カウント

int ReadPinDown()
{
  static int numMatch = 0;
  static int prevStat = HIGH;
  int stat = HIGH;
  int ret;
  
  stat = digitalRead(pinDownBtn);

  if( prevStat == stat ){
    numMatch++;
  }else{
#ifdef ARDUINO_AVR_UNO
   // Serial.println(numMatch, DEC);
#endif
    numMatch = 0;
    prevStat = stat;
  }

  if( 30 < numMatch ){ //30ms以上信号が安定すること
    ret = stat;
    numMatch = 0;
  }else{
    ret = prevStat;
  }
  
  return ret;
}
int ReadPinUp()
{
	static int numMatch = 0;
	static int prevStat = HIGH;
	int stat;
	int ret;
	
	stat = digitalRead(pinUpBtn);

	if( prevStat == stat ){
		numMatch++;
	}else{
		numMatch = 0;
		prevStat = stat;
	}

	if( 30 < numMatch ){ //30ms以上信号が安定すること
		ret = stat;
		numMatch = 0;
	}else{
		ret = prevStat;
	}
	
	return ret;
}
// the setup function runs once when you press reset or power the board
void setup() {
#ifdef ARDUINO_AVR_UNO
  Serial.begin(115200 );
  Serial.println("hello");
  pinMode(pinUpBtn, INPUT_PULLUP);
  pinMode(pinDownBtn, INPUT_PULLUP);
#else
  pinMode(pinUpBtn, INPUT);
  digitalWrite (pinUpBtn, HIGH); // enable pullup
  pinMode(pinDownBtn, INPUT);
  digitalWrite (pinDownBtn, HIGH); // enable pullup
#endif
  pinMode(pinDebug, OUTPUT);
  pinMode(pinLED, OUTPUT);
  digitalWrite(pinLED, HIGH); 
  
#if 0
  //OFF区間長の指定。600sec(default) -> 60sec -> 10sec
  offDuration = EEPROM.read(1) * 10; //EEPROMには10sec単位で保存する
  switch( offDuration ){
	case 600:	break;
	case 60:	break;
	case 10:	break;
	default:
		offDuration = 600;
		EEPROM.write(1, offDuration/10); //デフォルト値を書き込む
		break;
  }
  //ON区間長の指定。
  //0sec(default) -> 10sec -> 60sec
  onDuration = EEPROM.read(2) * 10; //EEPROMには10sec単位で保存する
  switch( onDuration ){
	  case 0:	break;
	  case 10:	break;
	  case 60:	break;
	  default:
		onDuration = 0;
		EEPROM.write(2, onDuration/10); //デフォルト値を書き込む
		break;
  }
#else

  statUp = digitalRead(pinUpBtn);
  statDown = digitalRead(pinDownBtn);
  secCurrent = 0;

#endif
}

void DoMMI_pushSW()
{
	
  prevDown = statDown;
  statDown = ReadPinDown();
  prevUp = statUp;
  statUp = ReadPinUp();

  if( LOW == prevUp && HIGH == statUp ){
	  switch( onDuration ){
		  case 0:	onDuration = 10; break;
		  case 10:	onDuration = 60; break;
		  case 60:	onDuration = 0; break;
		  default:  onDuration = 0; break;
	  }
	  secCurrent = 0;
	  EEPROM.write(2, onDuration/10); //新設定を書き込む
#ifdef ARDUINO_AVR_UNO
Serial.print("ON: ");
Serial.println(onDuration, DEC);
#endif	  
  }

  if( LOW == prevDown && HIGH == statDown ){
	  switch( offDuration ){
		  case 600:	offDuration = 60; break;
		  case 60:	offDuration = 10; break;
		  case 10:	offDuration = 600; break;
		  default:  offDuration = 600; break;
	  }
	  secCurrent = 0;
	  EEPROM.write(1, offDuration/10); //新設定を書き込む
#ifdef ARDUINO_AVR_UNO
Serial.print("OFF: ");
Serial.println(offDuration, DEC);
#endif
  }	
}

void DoMMI_DipSW()
{
  statDown = ReadPinDown();
  statUp = ReadPinUp();

  if( prevUp != statUp ){
    if( LOW == statUp ){
      onDuration = 10;
    }else{
      onDuration = 5;
    }
    secCurrent = 0;
    miliCurrent = 0;
  }

  if( prevDown != statDown ){
    if( LOW == statDown ){
      offDuration = 60;
    }else{
      offDuration = 120;
    }
    secCurrent = 0;
    miliCurrent = 0;
  } 

  prevDown = statDown;
  prevUp = statUp;
}

// the loop function runs over and over again forever
void loop() {

  unsigned long tim = millis();
  for(;;){ //wait for next 1ms period. 実際は1ループ1.032ms程度になる
    if( tim != millis() ){
      break; 
    }
  }

  //OS処理時間で8.125us
  //Loopで26.5usくらい。28KHz
  digitalWrite(pinDebug, HIGH);
  miliCurrent++;
  if( 970 < miliCurrent){
	  secCurrent++;
	  miliCurrent = 0;
  }
  
  //DoMMI_pushSW();
  DoMMI_DipSW();
  
  if( secCurrent < onDuration){
	digitalWrite(pinLED, HIGH);
  }else if( secCurrent < (onDuration + offDuration) ){
	digitalWrite(pinLED, LOW);  
  }else{
	secCurrent = 0;  
  }
 digitalWrite(pinDebug, LOW);
}
