#ifndef KHAZAD_ZYNQ_H
#define KHAZAD_ZYNQ_H
/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This is the KHAZAD_Zynq library header file, containing the functions and definitions 
to run the various applications of the design. The file defines these functions:
1.  USR_button_ISR
2.  board_configuration
3.  Zynq_crypt
4.  Zynq_crypt_simple
5.  test_vectors_full
6.  test_vectors_short
7.  demonstration
8.  hardware_implementation
9.  print_data
10. compare_blocks
11. about
Identical lines of code may appear in some of functions. This was done to ease the re-use of the functions 
as standalone programs.
*********************************************************************************************************
*********************************************************************************************************
Version 1.0: ECB implementation
*********************************************************************************************************
*********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "platform.h"
#include "xgpio.h"
#include "xgpiops.h"
#include "xparameters.h"
#include "xil_types.h"
#include "xstatus.h"
#include "Xscugic.h"
#include "xil_exception.h"
#include "nessie_modified.h"
#include "khazad-tweak32.h"

/********************************************************************************************************
*********************************************************************************************************
  Globals definitions
*********************************************************************************************************
*********************************************************************************************************/

// AXI_GPIO modules registers adresses:
#define ADDR0 ((unsigned int)0x41200000)
#define ADDR1 ((unsigned int)0x41210000)
#define ADDR2 ((unsigned int)0x41220000)
#define ADDR3 ((unsigned int)0x41230000)
#define ADDR_offset ((unsigned int)0x00000008)

// maximal length of input strings, in number of characters, including spaces:
#define MAX_LENGTH  400

/********************************************************************************************************
*********************************************************************************************************
  Global variables declarations
*********************************************************************************************************
*********************************************************************************************************/

static XGpioPs my_Gpio; // for the PS
static XGpio GPIO_3; 	// for the bidirectional module AXI_GPIO_3
static XScuGic my_Gic;  // for GIC: general interrupt controller
static u16 ctrl;		// for sending instructions to the PL design. Further details in main.c file.
static char *hex = "0123456789ABCDEF"; // for base conversion functions

/********************************************************************************************************
*********************************************************************************************************
  Functions definitions
*********************************************************************************************************
*********************************************************************************************************/

/********************************************************************************************************
  1. USR_button_ISR: the user button Interrupt Service Routine.
  The function communicates with the PL fabric. It makes use of the static variable ctrl 
  and configure it to give the appropriate instructions to the design.
*********************************************************************************************************/
static void USR_button_ISR(void *CallBackReff)
{
  XGpioPs_IntrDisablePin(&my_Gpio, 51); // for debouncing the switch
  XGpioPs_IntrClearPin(&my_Gpio, 51);	// clear the interrupt flag
  XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED
  ctrl = 0x0008; 		  // reset=1
  Xil_Out16(ADDR0,ctrl);  // send from PS to FPGA via AXI interface
  printf("\t\tReset was asserted!\n\r");
  sleep(1); 			  // for debouncing the switch
  ctrl = 0x0000; 		  // reset=0
  Xil_Out16(ADDR0,ctrl);
  XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the LED
  XGpioPs_IntrEnablePin(&my_Gpio, 51);
}

/********************************************************************************************************
  2. board_configuration: configures the PS, the peripherals, the bidirectional AXI_GPIO and the interrupt.
*********************************************************************************************************/
void board_configuration()
{
  XGpioPs_Config *GPIO_Config;
  GPIO_Config = XGpioPs_LookupConfig(XPAR_PS7_GPIO_0_DEVICE_ID);
  u16 status;
  status = XGpioPs_CfgInitialize(&my_Gpio, GPIO_Config, GPIO_Config->BaseAddr);
  if (status == XST_SUCCESS)
	printf("XGpioPs configuration successful! \n\r");
  else
	printf("XGpioPs configuration failed! \n\r");
  XGpioPs_SetDirectionPin(&my_Gpio, 47, 1); // board LED, output
  XGpioPs_SetOutputEnablePin(&my_Gpio, 47, 1);
  XGpioPs_SetDirectionPin(&my_Gpio, 51, 0); // USR button, input
  XGpioPs_SetDirectionPin(&my_Gpio, 54, 0); // EMIO pin, input
  status = XGpio_Initialize(&GPIO_3, XPAR_AXI_GPIO_3_DEVICE_ID); // bidirectional AXI_GPIO module
  if (status == XST_SUCCESS)
	printf("AXI_GPIO configuration successful! \n\r");
  else
	printf("AXI_GPIO configuration failed! \n\r");
  // Interrupt configuration:
  XScuGic_Config *Gic_Config;
  Gic_Config = XScuGic_LookupConfig(XPAR_PS7_SCUGIC_0_DEVICE_ID);
  status = XScuGic_CfgInitialize(&my_Gic, Gic_Config, Gic_Config->CpuBaseAddress);
  if (status == XST_SUCCESS)
    printf("GIC configuration successful! \n\r");
  else
    printf("GIC configuration failed! \n\r");
  Xil_ExceptionInit(); // initialize exception handlers on the processor
  Xil_ExceptionRegisterHandler(XIL_EXCEPTION_ID_INT, (Xil_ExceptionHandler)XScuGic_InterruptHandler, &my_Gic);
  status = XScuGic_Connect(&my_Gic, XPS_GPIO_INT_ID, (Xil_ExceptionHandler)USR_button_ISR, (void *)&my_Gic);
  if (status == XST_SUCCESS)
  	printf("GPIO interrupt handler connection successful! \n\r");
  else
  	printf("GPIO interrupt handler connection failed! \n\r");
  XGpioPs_SetIntrTypePin(&my_Gpio, 51, XGPIOPS_IRQ_TYPE_EDGE_RISING); // interrupt on rising edge
  XGpioPs_IntrClearPin(&my_Gpio, 51);  // clear any pending residual USR_button interrupts
  XGpioPs_IntrEnablePin(&my_Gpio, 51); // enable USR_button interrupt
  XScuGic_Enable(&my_Gic, XPS_GPIO_INT_ID); // enable GPIO interrupt (SPI: Shared Peripheral Interrupt)
  Xil_ExceptionEnable(); // enable interrupt handling
  XGpioPs_WritePin(&my_Gpio, 47, 1); // turn on the PS-ready indicator LED
}

/********************************************************************************************************
  3. Zynq_crypt: the main function that communicates with the PL fabric and get it to execute 
  a "crypt" operation: encryption or decryption. The function makes use of the static variable ctrl 
  and configure it to give the appropriate instructions to the design.
  Function parameters:
  text: pointer to u8 data in array.
  key1, key2, key3, key4: four u32 parts of the key.
  enc_dec: flag to the desired operation. enc_dec = 1: encryption, enc_dec = 0: decryption.
  only_data: indicates the key period. only_data = 1: new data, same key. only_data = 0: new data and new key.
  Function returns:
  result: pointer to u8 data out array.
*********************************************************************************************************/
void Zynq_crypt(const u8 * const text, const u32 key1, const u32 key2, const u32 key3, const u32 key4, const bool enc_dec, const bool only_data, u8 * const result)
{
  XGpioPs_WritePin(&my_Gpio, 47, 0); // turn off the PS-ready indicator LED
  // map u8-array text to two u32 d_in parts:
  u32 d_in_1 =
		((u32)text[0] << 24) ^
		((u32)text[1] << 16) ^
		((u32)text[2] <<  8) ^
		((u32)text[3]      );

  u32 d_in_2 =
		((u32)text[4] << 24) ^
		((u32)text[5] << 16) ^
		((u32)text[6] <<  8) ^
		((u32)text[7]      );

  if (!only_data)
  {
	  // send key:
	  Xil_Out32(ADDR1,key1)				 ;
	  Xil_Out32(ADDR1 + ADDR_offset,key2);
	  Xil_Out32(ADDR2,key3)				 ;
	  Xil_Out32(ADDR2 + ADDR_offset,key4);
  }
  // set GPIO_3 to output and send data:
  XGpio_SetDataDirection(&GPIO_3,1,0x00000000);
  Xil_Out32(ADDR3			   ,d_in_1);
  Xil_Out32(ADDR3 + ADDR_offset,d_in_2);

  // ctrl setting:
  ctrl = ctrl ^ 0x0001;   // toggle bit 0, to issue a start command
  if (enc_dec == 1)
	ctrl = ctrl | 0x0002; // = ctrl|0010, turn on bit 1
  else
	ctrl = ctrl & 0xFFFD; // = ctrl&1101, turn off bit 1
  if (only_data == 1)
	ctrl = ctrl | 0x0004; // = ctrl|0100, turn on bit 2
  else
	ctrl = ctrl & 0xFFFB; // = ctrl&1011, turn off bit 2

  Xil_Out16(ADDR0,ctrl);
  // can't send the start command before both key & data sent because key schedule will end before data has arrived,
  // and additional flags, and time to send them, will be needed.

  u16 finish;
  // set GPIO_3 to input and wait for data:
  XGpio_SetDataDirection(&GPIO_3,1,0xFFFFFFFF);
  do {
	finish = XGpioPs_ReadPin(&my_Gpio, 54); // read from FPGA via EMIO interface (polling)
	} while ((finish ^ ctrl) & 0x0001); // while LSB of finish != LSB of ctrl

  // read data from PL via AXI bus:
  u32 d_out_1 = Xil_In32(ADDR3);
  u32 d_out_2 = Xil_In32(ADDR3 + ADDR_offset);

  // map two u32 d_out parts to u8-array text:
  result[0] = (u8)(d_out_1 >> 24);
  result[1] = (u8)(d_out_1 >> 16);
  result[2] = (u8)(d_out_1 >>  8);
  result[3] = (u8)(d_out_1      );
  result[4] = (u8)(d_out_2 >> 24);
  result[5] = (u8)(d_out_2 >> 16);
  result[6] = (u8)(d_out_2 >>  8);
  result[7] = (u8)(d_out_2      );

  XGpioPs_WritePin(&my_Gpio, 47, 1); // turn on the LED
}

/********************************************************************************************************
  4. Zynq_crypt_simple: this function is very similar to Zynq_crypt, just a little more simple, 
  for use in the test vectors operations.
  The key is given as one parameter, a pointer to u8 array - reflecting the way it's calculated in the test vectors files, 
  and mapping to four u32 key parts is done inside the function. Also the function lacks the only_data option.
  One can easily create different versions of this function for other kinds of tests.
*********************************************************************************************************/
void Zynq_crypt_simple(const u8 * const text, const u8 * const key, const bool enc_dec, u8 * const result)
{
  XGpioPs_WritePin(&my_Gpio, 47, 0); // turn off the PS-ready indicator LED
  // map u8-array text to two u32 d_in parts:
  u32 d_in_1 =
		((u32)text[0] << 24) ^
		((u32)text[1] << 16) ^
		((u32)text[2] <<  8) ^
		((u32)text[3]      );

  u32 d_in_2 =
		((u32)text[4] << 24) ^
		((u32)text[5] << 16) ^
		((u32)text[6] <<  8) ^
		((u32)text[7]      );

  // map u8-array key to four u32 key parts:
  u32 key1 =
		((u32)key[ 0] << 24) ^
		((u32)key[ 1] << 16) ^
		((u32)key[ 2] <<  8) ^
		((u32)key[ 3]      );

  u32 key2 =
		((u32)key[ 4] << 24) ^
		((u32)key[ 5] << 16) ^
		((u32)key[ 6] <<  8) ^
		((u32)key[ 7]      );

  u32 key3 =
		((u32)key[ 8] << 24) ^
		((u32)key[ 9] << 16) ^
		((u32)key[10] <<  8) ^
		((u32)key[11]      );

  u32 key4 =
		((u32)key[12] << 24) ^
		((u32)key[13] << 16) ^
		((u32)key[14] <<  8) ^
		((u32)key[15]      );

  // send key:
  Xil_Out32(ADDR1,key1)					;
  Xil_Out32(ADDR1 + ADDR_offset,key2)	;
  Xil_Out32(ADDR2,key3)					;
  Xil_Out32(ADDR2 + ADDR_offset,key4)	;
  // set GPIO_3 to output and send data:
  XGpio_SetDataDirection(&GPIO_3,1,0x00000000);
  Xil_Out32(ADDR3			   ,d_in_1)	;
  Xil_Out32(ADDR3 + ADDR_offset,d_in_2)	;

  // ctrl setting:
  ctrl = ctrl ^ 0x0001;   // toggle bit 0, to issue a start command
  if (enc_dec == 1)
    ctrl = ctrl | 0x0002; // = ctrl|0010, turn on bit 1
  else
	ctrl = ctrl & 0xFFFD; // = ctrl&1101, turn off bit 1
  ctrl = ctrl & 0xFFFB;   // = ctrl&1011, turn off bit 2, only_data isn't active

  Xil_Out16(ADDR0,ctrl);
  // can't send the start command before both key & data sent because key schedule will end before data has arrived,
  // and additional flags, and time to send them, will be needed.

  u16 finish;
  // set GPIO_3 to input and wait for data:
  XGpio_SetDataDirection(&GPIO_3,1,0xFFFFFFFF);
  do {
	finish = XGpioPs_ReadPin(&my_Gpio, 54); // read from FPGA via EMIO interface (polling)
	} while ((finish ^ ctrl) & 0x0001); // while LSB of finish != LSB of ctrl

  // read data from PL via AXI bus:
  u32 d_out_1 = Xil_In32(ADDR3);
  u32 d_out_2 = Xil_In32(ADDR3 + ADDR_offset);
  
  // map two u32 d_out parts to u8-array text:
  result[0] = (u8)(d_out_1 >> 24);
  result[1] = (u8)(d_out_1 >> 16);
  result[2] = (u8)(d_out_1 >>  8);
  result[3] = (u8)(d_out_1      );
  result[4] = (u8)(d_out_2 >> 24);
  result[5] = (u8)(d_out_2 >> 16);
  result[6] = (u8)(d_out_2 >>  8);
  result[7] = (u8)(d_out_2      );

  XGpioPs_WritePin(&my_Gpio, 47, 1); // turn on the LED
}

/********************************************************************************************************
  5. test_vectors_full: this function is essentially the original reference code bctestvectors.c code, 
  combined with encryption and decryption on Zynq, to test the hardware implementation results.
  If these results are different than the reference code results, an error massage appears.
  This test includes a stage of 10^8 iterations, so it may take some time to be completed.
*********************************************************************************************************/
void test_vectors_full()
{
  struct NESSIEstruct subkeys;
  u8 key[KEYSIZEB];
  u8 plain[BLOCKSIZEB];
  u8 cipher[BLOCKSIZEB];
  u8 decrypted[BLOCKSIZEB];
  u32 i;
  int v;
  u8 Zynq_cipher[BLOCKSIZEB];
  u8 Zynq_decrypted[BLOCKSIZEB];

  printf("Test vectors -- set 1\n");
  printf("=====================\n\n");

  /* If key size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(KEYSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      key[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 1, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
		   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");
			   
      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
	    Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("Test vectors -- set 2\n");
  printf("=====================\n\n");

  /* If block size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(BLOCKSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      plain[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 2, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
			   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");

      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("Test vectors -- set 3\n");
  printf("=====================\n\n");

  for(v=0; v<256; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 3, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");

      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("Test vectors -- set 4\n");
  printf("=====================\n\n");

  for(v=0; v<4; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);

      printf("Set 4, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);

      for(i=0; i<99999999; i++)
        {
          memset(key, cipher[BLOCKSIZEB-1], KEYSIZEB);
          NESSIEkeysetup(key, &subkeys);
          NESSIEencrypt(&subkeys, cipher, cipher);
        }
	  print_data("Iterated 10^8 times", cipher, BLOCKSIZEB);
	  for(i=0; i<99999999; i++)
        {
          memset(key, Zynq_cipher[BLOCKSIZEB-1], KEYSIZEB);
		  Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
        }
	  print_data("Iterated 10^8 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("\n\nEnd of test vectors\n");
}

/********************************************************************************************************
  6. test_vectors_short: this function is identical to the previous one, 
  except the 10^8 iterations stage was shortened into 10^6 iterations.
  We recommend to use this test if time is short.
*********************************************************************************************************/
void test_vectors_short()
{
  struct NESSIEstruct subkeys;
  u8 key[KEYSIZEB];
  u8 plain[BLOCKSIZEB];
  u8 cipher[BLOCKSIZEB];
  u8 decrypted[BLOCKSIZEB];
  u32 i;
  int v;
  u8 Zynq_cipher[BLOCKSIZEB];
  u8 Zynq_decrypted[BLOCKSIZEB];

  printf("Test vectors -- set 1\n");
  printf("=====================\n\n");

  /* If key size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(KEYSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      key[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 1, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
		   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");
			   
      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
	    Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("Test vectors -- set 2\n");
  printf("=====================\n\n");

  /* If block size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(BLOCKSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      plain[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 2, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
			   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");

      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("Test vectors -- set 3\n");
  printf("=====================\n\n");

  for(v=0; v<256; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 3, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");

      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("Test vectors -- set 4 (shortened)\n");
  printf("=====================\n\n");

  for(v=0; v<4; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);

      printf("Set 4, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);

      for(i=0; i<999999; i++)
        {
          memset(key, cipher[BLOCKSIZEB-1], KEYSIZEB);
          NESSIEkeysetup(key, &subkeys);
          NESSIEencrypt(&subkeys, cipher, cipher);
        }
	  print_data("Iterated 10^6 times", cipher, BLOCKSIZEB);
	  for(i=0; i<999999; i++)
        {
          memset(key, Zynq_cipher[BLOCKSIZEB-1], KEYSIZEB);
		  Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
        }
	  print_data("Iterated 10^6 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      printf("\n");
    }

  printf("\n\nEnd of test vectors (shortened)\n");
}

/********************************************************************************************************
  7. demonstration: This function is designed to demonstrate the hardware implementation correctness.
  It prompts the user for key and for plaintext string data, then processes the data block by block.
  Each block is encrypted and then decrypted again. For each block the plaintext, the ciphertext, 
  the decrypted text (all three in hexadecimal ASCII code) and the block number are printed on screen.
  Comparisons are made between the plaintext and decrypted text of each block, and between 
  the original characters string and a decrypted re-calculated string.
  If a comparison fails, an error massage appears.
*********************************************************************************************************/
void demonstration()
{
  u32 key1, key2, key3, key4;
  bool go = 1;
  u8 data_string[MAX_LENGTH+1], decrypted_string[MAX_LENGTH+1], plain[BLOCKSIZEB], cipher[BLOCKSIZEB], decrypted[BLOCKSIZEB];
  printf("*************************************************************** \n\r");
  printf("Secret key configuration: \nKHAZAD is using a 128-bit key (32 figures in hexadecimal base). \n");
  printf("For your convenience, the key is entered in 4 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
  while (go)
  {
	  printf("Please enter key part number 1 \n");
	  scanf("%x", &key1);
	  printf("Please enter key part number 2 \n");
	  scanf("%x", &key2);
	  printf("Please enter key part number 3 \n");
	  scanf("%x", &key3);
	  printf("Please enter key part number 4 \n\r");
	  scanf("%x", &key4);
	  printf("key= %08X%08X%08X%08X \n", key1, key2, key3, key4);
	  printf("\nPlease enter data to encrypt (up to %d characters, including spaces) \n", MAX_LENGTH);
	  scanf(" %[^\r]s", data_string); // scanf format to allow reading spaces

	  u16 i = 0, j = 0, k = 0, block_num = 0;
	  while (data_string[i])
	  {
		  if (j < BLOCKSIZEB)
		  {
			  memset(plain+j, data_string[i], 1);
			  j++;
		  }

		  if ((j != BLOCKSIZEB) && !(data_string[i+1])) // residue exists
			  memset(plain+j, 0, BLOCKSIZEB-j); // zero padding

		  if (((j != BLOCKSIZEB) && !(data_string[i+1])) || (j == BLOCKSIZEB)) // need to encrypt
		  {
			  if (block_num == 0)
				Zynq_crypt(plain, key1, key2, key3, key4, 1, 0, cipher); // encryption, first operation: only_data = 0
			  else
				Zynq_crypt(plain, key1, key2, key3, key4, 1, 1, cipher); // encryption, not first operation: only_data = 1
			  Zynq_crypt(cipher, key1, key2, key3, key4, 0, 1, decrypted); // decryption, only_data = 1
			  printf("\n Text block number %u: \n", block_num);
			  print_data("plaintext", plain, BLOCKSIZEB);
			  print_data("ciphertext", cipher, BLOCKSIZEB);
			  print_data("decrypted text", decrypted, BLOCKSIZEB);
			  if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
				printf("** Decryption error: **\n    Decrypted ciphertext is different than the plaintext!\n\r");
			  for (k = 0; k < j; k++)
				decrypted_string[block_num*BLOCKSIZEB + k] = decrypted[k];
			  block_num++;
			  j = 0;
		  }
		  i++;
	  }

	  decrypted_string[i] = 0; // NULL character to end decrypted_string
	  printf("\nThe original string is: %s \n\r", data_string);
	  printf("The decrypted string is: %s \n\r", decrypted_string);
	  if (strcmp(data_string, decrypted_string) == 0)
	    printf("Texts identical! \n\r");
	  else
	    printf("ERROR: texts not identical! \n\r");

	  u8 answer;
	  bool valid_answer = 0;
	  do {
		  printf("Do you want to try this demonstration again? Please answer y/n \n\r");
		  scanf(" %c", &answer);
		  if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
			valid_answer = 1;
		  else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
		  {
			valid_answer = 1;
			go = 0;
			printf("Going back to the main menu... \n\r");
		  }
		  else
			printf("Not a valid input. \n\r");
	  } while (!valid_answer);
  }
  return;
}

/********************************************************************************************************
  8. hardware_implementation: A simple practical application.
  The user is prompted to choose between encryption mode or decryption mode.
  For encryption, a key and plaintext string are entered, 
  and the ciphertext is calculated and printed on screen as hexadecimal figures.
  For decryption, a key and ciphertext hexadecimal figures string are entered, 
  and the plaintext is calculated and printed on screen as regular characters.
*********************************************************************************************************/
void hardware_implementation()
{
  u32 key1, key2, key3, key4;
  bool enc_dec, valid_answer, first_run = 1, go = 1;
  u8 answer, data_in_string[MAX_LENGTH+1], cipher_in_string[MAX_LENGTH+1], block_in[BLOCKSIZEB], block_out[BLOCKSIZEB+1];
  printf("*************************************************************** \n\r");
  while (go)
  {
	do {
		  valid_answer = 0;
		  printf("For encryption, please press 'e'.  For decryption, please press 'd'. \n\r");
		  scanf(" %c", &answer);
		  if ((answer == 'e') || (answer == 'E'))
		  {
			valid_answer = 1;
			enc_dec = 1;  // =encryption
			printf("Encryption mode \n\r");
		  }
		  else if ((answer == 'd') || (answer == 'D'))
		  {
			valid_answer = 1;
			enc_dec = 0;  // =decryption
			printf("Decryption mode \n\r");
		  }
		  else
			printf("Not a valid input. \n\r");
		  } while (!valid_answer);

	if (!first_run)
	{
		valid_answer = 0;
		do {
			printf("Do you want to enter a new key? Please answer y/n \n\r");
			scanf(" %c", &answer);
			if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
				valid_answer = 1;
			else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
				valid_answer = 1;
			else
				printf("Not a valid input. \n\r");
		} while (!valid_answer);
	}

	if ((first_run) || ((!first_run) && ((answer == 'y') || (answer == 'Y') || (answer == '1'))))
	{
		printf("Secret key configuration: \nKHAZAD is using a 128-bit key (32 figures in hexadecimal base). \n");
		printf("For your convenience, the key is entered in 4 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
		printf("Please enter key part number 1 \n");
		scanf("%x", &key1);
		printf("Please enter key part number 2 \n");
		scanf("%x", &key2);
		printf("Please enter key part number 3 \n");
		scanf("%x", &key3);
		printf("Please enter key part number 4 \n\r");
		scanf("%x", &key4);
	}
	printf("key= %08X%08X%08X%08X \n", key1, key2, key3, key4);

	u16 i = 0;
	if (enc_dec == 1)  // plaintext input: use the input as is
	{
		printf("\nPlease enter data to encrypt (up to %d characters, including spaces) \n", MAX_LENGTH);
		scanf(" %[^\r]s", data_in_string);  // scanf format to allow reading spaces
		printf("\n\t the ciphertext: \n");
	}
	else  			   // ciphertext input: convert the input from hexadecimal figures string to characters string
	{
		printf("\nPlease enter data to decrypt - a sequence of hexadecimal figures pairs (up to %d characters) \n", MAX_LENGTH);
		scanf("%s", cipher_in_string);
		while (cipher_in_string[i])
		{
			char temp[] = {cipher_in_string[i],cipher_in_string[i+1]};  // each hexadecimal figures pair is the ASCII code of one character
			data_in_string[i/2] = (u8)strtol(temp, NULL, 16);			// convert hexadecimal string to long int to u8
			i+=2;
		}
		data_in_string[i/2] = 0;  // NULL character to end the string
		printf("\n\t the plaintext: \n");
	}

	block_out[BLOCKSIZEB] = 0;    // NULL character to end the string
	i = 0;
	u16 j = 0, k = 0, block_num = 0;
	while (data_in_string[i])
	{
		if (j < BLOCKSIZEB)
		{
			memset(block_in+j, data_in_string[i], 1);
			j++;
		}

		if ((j != BLOCKSIZEB) && !(data_in_string[i+1])) // residue exists
			memset(block_in+j, 0, BLOCKSIZEB-j); // zero padding

		if (((j != BLOCKSIZEB) && !(data_in_string[i+1])) || (j == BLOCKSIZEB)) // need to encrypt/decrypt
		{
			if ((block_num == 0) && ((first_run) || ((!first_run) && ((answer == 'y') || (answer == 'Y') || (answer == '1')))))
				Zynq_crypt(block_in, key1, key2, key3, key4, enc_dec, 0, block_out); // first operation: only_data = 0
			else
				Zynq_crypt(block_in, key1, key2, key3, key4, enc_dec, 1, block_out); // not first operation: only_data = 1
			if (enc_dec == 1)
				for (k=0; k < BLOCKSIZEB; k++) // ciphertext output: print as hexadecimal figures
				{
					putchar(hex[(block_out[k]>>4)&0xF]);
					putchar(hex[(block_out[k]   )&0xF]);
				}
			else
				printf("%s", block_out);      // plaintext output: print as characters

			block_num++;
			j = 0;
		}
		i++;
	}

	first_run = 0;
	valid_answer = 0;
	do {
		printf("\n\nDo you want to use this application again? Please answer y/n \n\r");
		scanf(" %c", &answer);
		if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
			valid_answer = 1;
		else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
		{
			valid_answer = 1;
			go = 0;
			printf("Going back to the main menu... \n\r");
		}
		else
			printf("Not a valid input. \n\r");
	   } while (!valid_answer);
  }
  return;
}

/********************************************************************************************************
  9. print_data: print a given string "str", then "=", then the ASCII code in hexadecimal figures of 
  each element in a given u8 array.
  From the reference code bctestvectors.c file.
*********************************************************************************************************/
void print_data(char *str, u8 *val, int len) // from reference code bctestvectors.c file
{
  int i;

  printf("%25s=", str);
  for(i=0; i<len; i++)
    {
      putchar(hex[(val[i]>>4)&0xF]);
      putchar(hex[(val[i]   )&0xF]);
    }
  putchar('\n');
}

/********************************************************************************************************
  10. compare_blocks: compare two u8 strings with the same given length.
  From the reference code bctestvectors.c file.
*********************************************************************************************************/
int compare_blocks(u8 *m1, u8 *m2, int len_bits)
{
  int i;
  int lenb=(len_bits+7)>>3;
  int mask0 = (1<<(((len_bits-1)&7)+1))-1;

  if((m1[0]&mask0) != (m2[0]&mask0))
    return 1;

  for(i=1; i<lenb; i++)
    if(m1[i] != m2[i])
        return 1;

  return 0;
}

/********************************************************************************************************
  11. about: print information about this project.
  When the design operates on bare-metal, there is no filesystem, so no text file can be used.
*********************************************************************************************************/
void about()
{
	printf("*********************************************************************************************************\n");
	printf("*********************************************************************************************************\n");
	printf("Zynq-7000 based Implementation of the KHAZAD Block Cipher\n");
	printf("Yossef Shitzer & Efraim Wasserman\n");
	printf("Jerusalem College of Technology - Lev Academic Center (JCT)\n");
	printf("Department of electrical and electronic engineering\n");
	printf("2018\n\r");

	printf("''The KHAZAD Legacy-Level Block Cipher'' is a block cipher designed by Paulo S.L.M. Barreto and Vincent Rijmen.\n");
	printf("It uses a 128-bit key, operates on 64-bit data blocks, and comprises 8 rounds.\n");
	printf("The algorithm has been submitted as a candidate for the first open NESSIE workshop in 2000.\n");
	printf("This first version now considered obsolete. For phase 2 of NESSIE, a modified version has been submitted, \n");
	printf("named ''Khazad-tweak'', and has been accepted as NESSIE finalist.\n");
	printf("This version can be found here:\n");
	printf("https://www.cosic.esat.kuleuven.be/nessie/tweaks.html\n\r");

	printf("The algorithm developers wrote: \n");
	printf("''Khazad is named after Khazad-dum, ''the Mansion of the Khazad'', which in the tongue of the Dwarves is \n");
	printf("the name of the great realm and city of Dwarrowdelf, of the haunted mithril mines in Moria, the Black Chasm.\n");
	printf("But all this should be quite obvious – unless you haven’t read J.R.R. Tolkien's ''The Lord of the Rings'', of course :-)  ''\n\r");

	printf("This hardware implementation of KHAZAD uses the MicroZed 7010 development board by Avnet Inc., \n");
	printf("which is based on a Xilinx Zynq-7010 All Programmable SoC.\n");
	printf("The Zynq Z-7010 device integrates a dual-core ARM Cortex A9 processor with an Artix-7 FPGA.\n");
	printf("This new concept allows many interesting and exciting possibilities.\n");
	printf("In our design, the programmable logic (PL) is used for implementing the algorithm, \n");
	printf("and the processing system (PS) is used mainly for dealing with user input & output operations.\n");
	printf("The PL design files were written in Verilog. Synthesis and Implementation were done using Xilinx Vivado.\n");
	printf("The PS program was written in C, and compiled using Xilinx SDK.\n\r");

	printf("The MicroZed development board can be used as both a stand-alone board, \n");
	printf("or combined with a carrier card as an embeddable system-on-module.\n");
	printf("This implementation was designed to be fully operational even when using the stand-alone mode.\n");
	printf("Plugging the board into the carrier card will activate more indicator LEDs.\n\r");

	printf("This project was created as a final year project, with the guidance of Mr. Uri Stroh.\n");
	printf("We want to thank Mr. Stroh for his guidance and help, \n");
	printf("the Lev Academic Center (JCT) staff for supplying equipment and technical support, \n");
	printf("and the Xilinx and Avnet companies for their fine products, useful documentation and helpful websites.\n\r");
}


#endif
