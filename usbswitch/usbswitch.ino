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

static bool StatusUSB = true;
static bool Status5V = false; 
static bool Status3_3V = false;
static bool StatusAlwaysON; 

// the setup function runs once when you press reset or power the board
void setup() {
  
  pinMode(8, OUTPUT); //5V Relay
  pinMode(7, OUTPUT); //USB VCC Relay
  pinMode(6, OUTPUT); //USB D- Relay
  pinMode(5, OUTPUT); //USB D+ Relay
  pinMode(9, OUTPUT); //3.3V PMOSFET
  pinMode(10, OUTPUT); //Yellow Status LED
  pinMode(16, OUTPUT); //Green Status LED
  pinMode(15, INPUT_PULLUP ); //Always ON/USB Controlled switch

  Serial.begin(9600, SERIAL_8N1 );

  Set5V(false);
  Set3_3V(false);
  digitalWrite(10, LOW); //Yellow Status LED
  digitalWrite(16, LOW);  //Green Status LED  
  ConnectUSB();

  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
  Serial.println("[I] USB switcher booted up.");
  digitalWrite(10, HIGH); //Yellow Status LED
  digitalWrite(16, HIGH);  //Green Status LED  
}

void Set5V(bool s)
{
  Status5V = s;
  if(s){
    digitalWrite(8, LOW); //5V ON
  }else{
    digitalWrite(8, HIGH); //5V OFF
  }
}

void Set3_3V(bool s)
{
  Status3_3V = s;
  if(s){
    digitalWrite(9, LOW); //3.3V ON
  }else{
    digitalWrite(9, HIGH); //3.3V OFF
  }
}
void ConnectUSB()
{
  digitalWrite(7, HIGH); // USB VCC Connect
  delay(100);
  digitalWrite(6, HIGH);  //USB D- Relay Connect
  digitalWrite(5, HIGH);  //USB D+ Relay Connect  
  StatusUSB = true;
}

void DisconnectUSB()
{
  StatusUSB = false;
  digitalWrite(6, LOW);  //USB D- Relay Disconnect
  digitalWrite(5, LOW);  //USB D+ Relay Disconnect  
  delay(100);
  digitalWrite(7, LOW); // USB VCC Disconnect
}

void AlwaysOn()
{
  Set5V(true);
  delay(100);
  Set3_3V(true);  
  ConnectUSB();
  digitalWrite(10, LOW); //Yellow Status LED
}

void USBcontrolled()
{
  Set3_3V(false);  
  delay(100);
  Set5V(false);
  DisconnectUSB();
  digitalWrite(10, HIGH); //Yellow Status LED
}

static char serialReadBuf[16];
static int serialReadPos = 0;


void OnSingleLine(String line)
{
  String s;
  Serial.print("[");
  Serial.print(line);
  Serial.print("] ");

  if( line.equalsIgnoreCase( "?" ) ){
    Serial.println( "OK, available commands: q, enausb, disusb, ena3_3v, dis3_3v, ena5v, dis5v" );
            digitalWrite(10, LOW); //Yellow Status LED
  }else if( line.equalsIgnoreCase( "q" ) ){
    Serial.print( "OK, " );
    s = "5V:";
    s += Status5V;
    s += ", 3_3V:";
    s += Status3_3V;
    s += ", USB:";
    s += StatusUSB;
    s += ", MODE:";
    if( StatusAlwaysON ){
      s += "AlwaysON";
    }else{
      s += "USBcontrolled";
    }
    Serial.print( s );
    Serial.println( "" );
    
  }else if( line.equalsIgnoreCase( "enausb" ) ){
    if( StatusAlwaysON ){
      Serial.println( "ERROR, unable to control under Always ON mode." );
    }else{
      ConnectUSB();
      Serial.println( "OK." );
    }
    
  }else if( line.equalsIgnoreCase( "disusb" ) ){
    if( StatusAlwaysON ){
      Serial.println( "ERROR, unable to control under Always ON mode." );
    }else{
      DisconnectUSB();
      Serial.println( "OK." );
    }
    
  }else if( line.equalsIgnoreCase( "ena3_3v" ) ){
    if( StatusAlwaysON ){
      Serial.println( "ERROR, unable to control under Always ON mode." );
    }else{
      Set3_3V(true);
      Serial.println( "OK." );
    }
    
  }else if( line.equalsIgnoreCase( "dis3_3v" ) ){
    if( StatusAlwaysON ){
      Serial.println( "ERROR, unable to control under Always ON mode." );
    }else{
      Set3_3V(false);
      Serial.println( "OK." );
    }
    
  }else if( line.equalsIgnoreCase( "ena5v" ) ){
    if( StatusAlwaysON ){
      Serial.println( "ERROR, unable to control under Always ON mode." );
    }else{
      Set5V(true);
      Serial.println( "OK." );
    }
    
  }else if( line.equalsIgnoreCase( "dis5v" ) ){
    if( StatusAlwaysON ){
      Serial.println( "ERROR, unable to control under Always ON mode." );
    }else{
      Set5V(false);
      Serial.println( "OK." );
    }
    
  }else{
    Serial.println( "ERROR, Unknown command." );
  }
}

int FeedChar(int c)
{
  if( 0x0D == c || 0x0A == c ){ //is it CR or LF?
    if( 0 != serialReadPos ){
      serialReadBuf[serialReadPos] = '\0';
      String line = serialReadBuf;
      //Serial.println( line );
      OnSingleLine(line);
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
  }
  
  return 0;
}

// the loop function runs over and over again forever
void loop() {
  int sw;
  static int prevSw = 4949;
  static int count;

  delay(10);
  count++;
  
  if( 0 == (count % 50 ) ){ //blinking Status LED
    digitalWrite(16, HIGH);  //Green Status LED  
  }else if( 25 == (count % 50 ) ){
    digitalWrite(16, LOW);  //Green Status LED  
  }
  
  sw = digitalRead(15);
  if( sw != prevSw ){
    if( HIGH == sw ){
      StatusAlwaysON = false;
      USBcontrolled();
    }else{
      StatusAlwaysON = true;
      AlwaysOn();
    }
  }
  prevSw = sw;
  
  if (0 < Serial.available() ) {
    FeedChar( Serial.read() );
  }
}
