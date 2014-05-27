// Python-serial controlled sniffer
// Commands are :
// 10 : return 1 if nrf24 initialisation was OK, 0 otherwise
// 20 : return 1 if nrf24RX initialisation was OK, 0 otherwise
// 30 X : set listenning channel to X (one byte value between 0 and 127)
// 40 : return the currently tuned channel
// 50 : return 0 if no packet is available, return 1 and 32 bytes of packet otherwise.
// 60 X A B [C [D [E]]]:  with X being either 2,3,4, or 5 and followed X bytes (A B [C[D[E]]]). Set listening address to AB[C[D[E]]]

#include <NRF24.h>
#include <SPI.h>

// Singleton instance of the radio
NRF24 nrf24;
uint8_t nrf24_packet_buffer[32]; 
unsigned char channel;

void setup() 
{
  delay(5*1000); // startup delay, helps re-flashing the arduino in case of "oops".

  channel = 1;

  Serial.begin(115200);

  // I really should check the return value of those...
  nrf24.init();
  nrf24.setRF(NRF24::NRF24DataRate2Mbps, NRF24::NRF24TransmitPowerm18dBm);  
  nrf24.powerUpSNIFF(); // replace powerupRx
}

void loop()
{
  uint8_t i;  
  int serial_buffer = 0;
  
  while (1) {
      if (Serial.available() > 0) {
          //there's at least one byte of data available :)
          serial_buffer = Serial.read();
          if (serial_buffer==40) {
              Serial.write((byte)channel);
          } else if (serial_buffer==30) {
              int tmp_channel;
              while ((tmp_channel = Serial.read())==-1) {}
              channel = tmp_channel; 
              nrf24.setChannel(channel);
          } else if (serial_buffer==50) {
              unsigned char len=32;
              if (nrf24.recv((uint8_t*)&nrf24_packet_buffer, &len)) {
                  Serial.write((byte)1);
                  Serial.write(nrf24_packet_buffer, len);
              } else {
                  Serial.write((byte)0);
              }
          } else if (serial_buffer==60) {
              int tmp_len=0;
              while ((tmp_len = Serial.read())==-1) {}
              
              unsigned char new_addr[5];
              int tmp_addr;
              while ((tmp_addr = Serial.read())==-1) {}
              new_addr[0] = tmp_addr; Serial.write(new_addr[0]);
              while ((tmp_addr = Serial.read())==-1) {}
              new_addr[1] = tmp_addr; Serial.write(new_addr[1]);
              
              if (tmp_len>2) {
                while ((tmp_addr = Serial.read())==-1) {}
                new_addr[2] = tmp_addr; Serial.write(new_addr[2]);
              }
              if (tmp_len>3) {
                while ((tmp_addr = Serial.read())==-1) {}
                new_addr[3] = tmp_addr; Serial.write(new_addr[3]);
              }
              if (tmp_len>4) {
                while ((tmp_addr = Serial.read())==-1) {}
                new_addr[4] = tmp_addr; Serial.write(new_addr[4]);
              }
              nrf24.setAddressWidth(tmp_len-2);
              nrf24.setPipeAddress(0, (uint8_t*)new_addr, tmp_len);
          }
      }
  }
}

