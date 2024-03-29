#include <clocks.h>
#include "pico_rosc.h"
#include "pico_sleep.h"
#include <Servo.h>

const int analogInPin = A0; 
int adcVal;
const int pinServo1 = 8;
Servo servo1;
const int pinServo2 = 9;
Servo servo2;
int servoDeg = 0;

#define NUM_BTN 3
const int pinBtn[NUM_BTN] = {2,3,4};
int statusBtn[NUM_BTN] = {1,1,1};
int prevStatusBtn[NUM_BTN] = {1,1,1};

#define MODE_INTERNAL_LR_SYNC 0
#define MODE_INTERNAL_LR_INV 1
#define MODE_EXTERNAL 2
#define MODE_SLEEP 3
int modeControl = MODE_INTERNAL_LR_SYNC;
int depthDeg = 90; // -90 ... +90 
int speedDeg = 2; //1 deg per 20ms
int direction = 1;

#define N_MOVING_AVG 8 //must be 2^n
int avgBuf[N_MOVING_AVG] = {0};
int avgBufPos = 0;

int FeedMovingAvg(int val)
{
  avgBuf[avgBufPos] = val;
  int i;
  int ret = 0;
  for( i = 0 ; i < N_MOVING_AVG; i++ ){
    ret += avgBuf[i];
  }
  ret /= N_MOVING_AVG;
  avgBufPos++;
  avgBufPos &= (N_MOVING_AVG-1);
  return ret;
}

void setup() {
  // put your setup code here, to run once:
#ifdef ARDUINO_AVR_UNO
  Serial.begin(115200);
  Serial.println("hello");
#endif
  int i;
  for(i = 0; i < NUM_BTN; i++){
    pinMode(pinBtn[i], INPUT_PULLUP);
  }
  pinMode(pinServo1, OUTPUT);
  digitalWrite(pinServo1, LOW);
  pinMode(pinServo2, OUTPUT);
  digitalWrite(pinServo2, LOW);
  analogReadResolution(12);
  delay(2);
  servo1.attach(pinServo1, 544, 2400); //544us@0deg, 2400us@180deg for SG90
  servo2.attach(pinServo2, 544, 2400); //544us@0deg, 2400us@180deg for SG90
}

void OnModeBtn()
{
  modeControl++;

  if(MODE_SLEEP < modeControl){
    modeControl = MODE_INTERNAL_LR_SYNC;
  }
  if(MODE_SLEEP == modeControl){
    //entering dormant
    digitalWrite(25, LOW); //turn off LED
    Serial.end();
    #if defined(USE_TINYUSB)
    USBDevice.detach();
    #endif
    sleep_run_from_xosc();
    sleep_goto_dormant_until_pin(pinBtn[0], 0, LOW);
    // back from dormant state
    rosc_enable();
    clocks_init();
    Serial.begin(115200);
    modeControl = MODE_INTERNAL_LR_SYNC;
    //rp2040.reboot();
  }
}

void OnDepthBtn()
{
  depthDeg += 30;
  if(90 < depthDeg ){
    depthDeg = 30;
  }
}

void OnSpeedBtn()
{
  speedDeg+=2;
  if( 10 < speedDeg){
    speedDeg = 2;
  }
}

void BtnProc()
{
  int i;
  for(i = 0; i < NUM_BTN; i++){
    prevStatusBtn[i] = statusBtn[i];
    statusBtn[i] = digitalRead(pinBtn[i]);
  }

  if(0 == prevStatusBtn[0] && 1 == statusBtn[0]){
    OnModeBtn();
  }
  else if(0 == prevStatusBtn[1] && 1 == statusBtn[1]){
    OnDepthBtn();
  }
  else if(0 == prevStatusBtn[2] && 1 == statusBtn[2]){
    OnSpeedBtn();
  }
}

int zeroCenterDeg = 0;

void loop() {
  unsigned long tim = millis();
  for(;;){ //wait for next 1ms period. 実際は1ループ1.032ms程度になる
    if( tim != millis() ){
      break; 
    }
  }
  char buf[256];

  if(0 == (tim & 1023)){
    static int ledStatus = LOW;
    if(LOW == ledStatus){
      ledStatus = HIGH;
    }
    else{
      ledStatus = LOW;
    }
    digitalWrite(25, ledStatus);
  }

  if( 0 == (tim % 20)){ //PWM 50Hz
    BtnProc();
    if(MODE_INTERNAL_LR_SYNC == modeControl || MODE_INTERNAL_LR_INV == modeControl){
      zeroCenterDeg += (direction * speedDeg);

      if( zeroCenterDeg < depthDeg*(-1) ){
        direction = 1;
        zeroCenterDeg = depthDeg*(-1);
      }
      else if( depthDeg < zeroCenterDeg){
        direction = -1;
        zeroCenterDeg = depthDeg;
      }
      sprintf(buf, "%d, %d, %d, %d, %d", zeroCenterDeg, direction, speedDeg, depthDeg,modeControl);
      Serial.println(buf);

      servoDeg = zeroCenterDeg + 90;

      if(MODE_INTERNAL_LR_SYNC == modeControl ){
        servo1.write(servoDeg);
        servo2.write(servoDeg);
      }
      else{ //LR Invert
        servo1.write(servoDeg);
        servo2.write(180 - servoDeg);
      }
    }
    else if(MODE_EXTERNAL == modeControl){
      int adcValRaw = analogRead(analogInPin); //12bit
      adcValRaw = FeedMovingAvg(adcValRaw);
      adcVal = adcValRaw >> 3; // to 9bit
      servoDeg = (adcVal*45) >> 7; // 180/512 = 45/128
      if( servoDeg < 0){ servoDeg = 0; }
      if( 180 < servoDeg){servoDeg = 180; }
      sprintf(buf, "%d, %d, %d, %d, %d", servoDeg, adcValRaw, statusBtn[0], statusBtn[1],statusBtn[2]);
      Serial.println(buf);

      servo1.write(servoDeg);
      servo2.write(servoDeg);
    }
    else{ //Sleep
      delay(100);
    }
  }
}
