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


// the setup function runs once when you press reset or power the board
void setup() {
  // initialize digital pin 13 as an output.
  pinMode(8, OUTPUT); //5V Relay
  pinMode(7, OUTPUT); //USB VCC Relay
  pinMode(6, OUTPUT); //USB D- Relay
  pinMode(5, OUTPUT); //USB D+ Relay
  pinMode(9, OUTPUT); //3.3V PMOSFET
  pinMode(10, OUTPUT); //Yellow Status LED
  pinMode(16, OUTPUT); //Green Status LED
 }

// the loop function runs over and over again forever
void loop() {
  digitalWrite(8, HIGH);   // turn the LED on (HIGH is the voltage level)
  digitalWrite(7, HIGH); 
  digitalWrite(6, HIGH);   // turn the LED on (HIGH is the voltage level)
  digitalWrite(5, HIGH); 
  digitalWrite(9, HIGH);   // turn the LED on (HIGH is the voltage level)
  digitalWrite(10, HIGH);
  digitalWrite(16, LOW); 
  delay(1000);              // wait for a second
  digitalWrite(8, LOW);    // turn the LED off by making the voltage LOW
  digitalWrite(7, LOW);
  delay(100); 
  digitalWrite(6, LOW);    // turn the LED off by making the voltage LOW
  digitalWrite(5, LOW);
  digitalWrite(9, LOW);    // turn the LED off by making the voltage LOW
  digitalWrite(10, LOW);
  digitalWrite(16, HIGH); 
  delay(2000);              // wait for a second
}
