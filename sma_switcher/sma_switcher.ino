#define NUM_PORTS 4
static bool isPortSelectB[NUM_PORTS+1] = {false}; // array of 1 origin

void setup() {
  // put your setup code here, to run once:
  pinMode(5, OUTPUT); //Port1 NMOSFET
  digitalWrite(5, LOW);
  pinMode(4, OUTPUT); //Port2 NMOSFET
  digitalWrite(4, LOW);
  pinMode(3, OUTPUT); //Port3 NMOSFET
  digitalWrite(3, LOW);
  pinMode(2, OUTPUT); //Port4 NMOSFET
  digitalWrite(2, LOW);

  pinMode(10, OUTPUT); //Yellow Status LED
  digitalWrite(10, LOW); //Yellow Status LED
  
  pinMode(16, OUTPUT); //Green Status LED
  digitalWrite(16, LOW);  //Green Status LED  

  Serial.begin(9600, SERIAL_8N1 );
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
  Serial.println("[I] 4port SMA switcher booted up.");

}

static char serialReadBuf[16];
static int serialReadPos = 0;

void DoSelect(int port, bool isSelB)
{
  switch(port){
    case 1: digitalWrite(5, isSelB); isPortSelectB[port] = isSelB; break;
    case 2: digitalWrite(4, isSelB); isPortSelectB[port] = isSelB; break;
    case 3: digitalWrite(3, isSelB); isPortSelectB[port] = isSelB; break;
    case 4: digitalWrite(2, isSelB); isPortSelectB[port] = isSelB; break;
    default: break;
  }
  
}

const char *ToStringSel(bool isSelB)
{
  if(isSelB){
    return "B";
  }
  else{
    return "A";
  }
}
void OnSingleLine(String line)
{
  String s;
  Serial.print("[");
  Serial.print(line);
  Serial.print("] ");

  if( line.equalsIgnoreCase( "?" ) ){
    Serial.println( "OK, available commands: q, sel1a, sel1b, sel2a, sel2b, sel3a, sel3b, sel4a, sel4b" );
            digitalWrite(10, LOW); //Yellow Status LED
  }else if( line.equalsIgnoreCase( "q" ) ){
    Serial.print( "OK, " );
    int i;
    for(i = 1; i <= NUM_PORTS; i++){
      Serial.print(i);
      Serial.print(":");
      Serial.print(ToStringSel(isPortSelectB[i]));
      Serial.print(", ");
    }
    Serial.println( "" );
    
  }else if( line.equalsIgnoreCase( "sel1a" ) ){
    DoSelect(1, false);
    Serial.println( "OK." );
    
  }else if( line.equalsIgnoreCase( "sel1b" ) ){
    DoSelect(1, true);
    Serial.println( "OK." );
    
  }else if( line.equalsIgnoreCase( "sel2a" ) ){
    DoSelect(2, false);
    Serial.println( "OK." );
    
  }else if( line.equalsIgnoreCase( "sel2b" ) ){
    DoSelect(2, true);
    Serial.println( "OK." );
    
  }else if( line.equalsIgnoreCase( "sel3a" ) ){
    DoSelect(3, false);
    Serial.println( "OK." );
    
  }else if( line.equalsIgnoreCase( "sel3b" ) ){
    DoSelect(3, true);
    Serial.println( "OK." );
    
  }else if( line.equalsIgnoreCase( "sel4a" ) ){
    DoSelect(4, false);
    Serial.println( "OK." );
    
  }else if( line.equalsIgnoreCase( "sel4b" ) ){
    DoSelect(4, true);
    Serial.println( "OK." );
    
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

void loop() {
  // put your main code here, to run repeatedly:
  int sw;
  static int prevSw = 4949;
  static int count;

  delay(50); //20fps
  count++;
  
  if( 0 == (count % 20 ) ){ //blinking Status LED
    digitalWrite(16, HIGH);  //Green Status LED  
  }else if( 10 == (count % 20 ) ){
    digitalWrite(16, LOW);  //Green Status LED  
  }
 
  if (0 < Serial.available() ) {
    FeedChar( Serial.read() );
  }
}
