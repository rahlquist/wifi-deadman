//code entirely based on https://github.com/AndreasFischer1985/ESP32-MAC-Scanner 

#include "esp_wifi.h"

bool debugMode = false;
String macList[300][3]; //macList stores MAC, timer & channel for up to 100 MACs
String macList2[10][2] = {  
  {"MyMAC1","E8:DF:70:C3:5C:4B"},
  {"MyMAC2","28:DF:EB:F9:8B:3E"}
};

int maxMacs  =  sizeof macList  / sizeof macList[0];
int maxMacs2 =  sizeof macList2 / sizeof macList2[0];
int length_of_miss = 600; //how long in seconds you want to wait between misses before triggering react()
int relay_pin = 22; //relay pin
int knownMacs = 0;
int channel = 1;//starting wifi channel
int timer = 0; // Set to 0 or less for infinite duration of entries
bool matchedthis = false; //currently unused
time_t start_t, end_t;
double diff_t;

const wifi_promiscuous_filter_t filt={
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};

typedef struct { 
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

typedef struct { 
  int16_t fctl;
  int16_t duration;
  MacAddr da;
  MacAddr sa;
  MacAddr bssid;
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { 
  int channel1 = channel;
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  int len = p->rx_ctrl.sig_len;
  WifiMgmtHdr *wh = (WifiMgmtHdr*)p->payload;
  len -= sizeof(WifiMgmtHdr);
  if (len < 0) return;
  String packet;
  String mac;
  String info;
  int fctl = ntohs(wh->fctl);
  for(int i=0;i<=20;i++){ // i <=  len
     String hpay=String(p->payload[i],HEX);
     if(hpay.length()==1)hpay="0"+hpay;
     packet += hpay;
  }
  for(int i=10;i<=15;i++){ // extract MAC address 
     String hpay=String(p->payload[i],HEX);
     if(hpay.length()==1)hpay="0"+hpay;
     mac += hpay;
     if(i<15)mac+=":";
  }
  mac.toUpperCase();
  info="MAC = " + mac + " channel=" + channel1 + " in " + packet+"(...)";
  int added = 0;
  for(int i=0;i<=maxMacs;i++){ // check if MAC address is known
    if(mac == macList[i][0]){ // if the MAC address is known, reset the time remaining 
      macList[i][1] = String(timer);
      added = 1;
    }
  }
  int matched = 0;
  for(int ii=0;ii<=maxMacs2;ii++){ // check if MAC address is a match
    if(mac == macList2[ii][1]){ // if the MAC address is set flag to skip adding to array 
      //macList2[r][1] = String(timer);
      matched = 1;
      diff_t = 0;
      time(&start_t);
          digitalWrite(LED_BUILTIN, HIGH);
          digitalWrite(relay_pin, HIGH);       
    }
  }

  if(added == 0 && matched == 0){ // Add new entry to the array if added==0
    macList[knownMacs][0] = mac;
    macList[knownMacs][1] = String(timer);
    macList[knownMacs][2] = String(channel);
    if (debugMode == true) 
      Serial.println(info);
    else     
      //Serial.printf("\r\n%d MACs detected.\r\n",knownMacs);
    knownMacs ++;
    if(knownMacs > maxMacs){
      Serial.println("Warning: MAC overflow");
      knownMacs = 0;
    }
  }
}

void updateTimer(){ // update time remaining for each known device
  for(int i=0;i<maxMacs;i++){
    if(!(macList[i][0] == "")){
      int newTime = (macList[i][1].toInt());
      newTime --;
      if(newTime <= 0){
        macList[i][1] = String(timer);
      }else{
        macList[i][1] = String(newTime);
      }
    }
  }
}

void showMyMACs(){ // show the MACs that are on both macList and macList2.
  String res = "";
  int counter=0;
  for(int i=0;i<maxMacs;i++){
    if(!(macList[i][0] == "")){
      for(int j=0;j<maxMacs2;j++){
        if(macList[i][0] == macList2[j][1]){
          counter += 1;
          res += (String(counter) +  ". MAC=" + macList[i][0] + "  ALIAS=" + macList2[j][0] + "  Channel=" + macList[i][2] + "  Timer=" + macList[i][1] + "\r\n");
          Serial.print("\r\n"+(String(counter) +  ". MAC=" + macList[i][0] + "  ALIAS=" + macList2[j][0] + "  Channel=" + macList[i][2] + "  Timer=" + macList[i][1] + "\r\n"));
          time(&start_t);
          digitalWrite(LED_BUILTIN, HIGH);
          digitalWrite(relay_pin, HIGH); 
          //digitalWrite(LED, HIGH);
          //macList[i][0] = "";
          //matchedthis = true;
        }
      }
    }
  }
}

void react() {
  time(&start_t);
  digitalWrite(LED_BUILTIN, LOW);
  digitalWrite(relay_pin, LOW); 
  Serial.println("REACTED");

}

void setup() {
  Serial.begin(115200);
  //Serial.printf("\n\nSDK version:%s\n\r", system_get_sdk_version());
  pinMode(LED_BUILTIN, OUTPUT);
  pinMode (relay_pin, OUTPUT);
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  //pinMode(LED, OUTPUT);
}

void loop() {
    diff_t = 0;    
    if(channel > 14) channel = 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    delay(1000);
    if (timer>0) updateTimer();
    if (debugMode == false) showMyMACs();
    channel++;    
    time(&end_t);
    diff_t = difftime(end_t, start_t);
    if (diff_t > length_of_miss) {      
      time(&end_t);
      time(&start_t);
      //Serial.println(String(start_t));
      //Serial.println(String(end_t));
      //Serial.println(String(diff_t));
      react();
      delay(10000);
    }else{
      Serial.print("diff ");
    Serial.println(diff_t);
    }
    //for(int v = 0; v < maxMacs; v++)
        {
          //Serial.println(". MAC=" + macList[v][0] + "  Channel=" + macList[v][2] + "  Timer=" + macList[v][1] +" Count=" + String(v));
        }
delay(2000);

}
