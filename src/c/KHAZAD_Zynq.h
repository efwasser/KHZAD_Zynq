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
1.  board_configuration
2.  USR_button_ISR
3.  Zynq_crypt
4.  Zynq_crypt_simple
5.  test_vectors
6.  demonstration
7.  HW_application
8.  NESSIEencrypt_CBC
9.  NESSIEdecrypt_CBC
10. SW_application
11. CBC_MAC
12. PRNG
13. random_vectors_test
14. PRNG_application
15. print_data
16. compare_blocks
17. about
18. performance_measurement (testing mode only)
Identical lines of code may appear in some of functions. This was done to ease the re-use of the functions 
as standalone programs.
*********************************************************************************************************
*********************************************************************************************************
Version 3.0: ECB & CBC implementation, Hardware & Software
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
  Global definitions
*********************************************************************************************************
*********************************************************************************************************/


// AXI_GPIO modules registers addresses:
#define ADDR0 ((unsigned int)0x41200000)
#define ADDR1 ((unsigned int)0x41210000)
#define ADDR2 ((unsigned int)0x41220000)
#define ADDR3 ((unsigned int)0x41230000)
#define ADDR4 ((unsigned int)0x41240000)
#define ADDR_offset ((unsigned int)0x00000008)

// maximal length of input strings, in number of characters, including spaces:
#define MAX_LENGTH  100

// number of data blocks for each message in the random vectors test:
#define BLOCKS_NUM  4


/********************************************************************************************************
*********************************************************************************************************
  Global variables
*********************************************************************************************************
*********************************************************************************************************/


static XGpioPs my_Gpio; // for the PS
static XGpio GPIO_4; 	// for the bidirectional module AXI_GPIO_4
static XScuGic my_Gic;  // for GIC: general interrupt controller
static u16 ctrl;		// for sending instructions to the PL design. Further details in main.c file.
static char *hex = "0123456789ABCDEF"; // for base conversion functions
// PRNG variables:
static u32 counter = 0;
static u8 nonce[BLOCKSIZEB/2] = {1, 2, 3, 4}; // random value
static u8 PRNG_key[KEYSIZEB] = {0};			  // random value
// nonce and PRNG_key are parts of the random stream seed.
// For cryptographic purposes, this data should be kept secret, and not used twice.


/********************************************************************************************************
*********************************************************************************************************
  Functions declarations
*********************************************************************************************************
*********************************************************************************************************/


void board_configuration();
static void USR_button_ISR(void *CallBackReff);
void Zynq_crypt(const u8 * const text, const u32 key1, const u32 key2, const u32 key3, const u32 key4, const u32 IV1, const u32 IV2, const bool only_data, const bool enc_dec, const bool op_mode, const bool first_block, const bool new_IV, u8 * const result);
void Zynq_crypt_simple(const u8 * const text, const u8 * const key, const bool enc_dec, u8 * const result);
void test_vectors();
void demonstration();
void HW_application();
void NESSIEencrypt_CBC(const struct NESSIEstruct * const structpointer, const u8 * const plaintext, u8 * const CBC_Xor, u8 * const ciphertext);
void NESSIEdecrypt_CBC(const struct NESSIEstruct * const structpointer, const u8 * const ciphertext, u8 * const CBC_Xor, u8 * const plaintext);
void SW_application();
void CBC_MAC();
void PRNG(u8 * const result);
void random_vectors_test();
void PRNG_application();
void print_data(char *str, u8 *val, int len);
int compare_blocks(u8 *m1, u8 *m2, int len_bits);
void about();
void performance_measurement();

/********************************************************************************************************
*********************************************************************************************************
  Functions definitions
*********************************************************************************************************
*********************************************************************************************************/


/********************************************************************************************************
  1. board_configuration: configures the PS, the peripherals, the bidirectional AXI_GPIO and the interrupt.
*********************************************************************************************************/
void board_configuration()
{
  XGpioPs_Config *GPIO_Config;
  GPIO_Config = XGpioPs_LookupConfig(XPAR_PS7_GPIO_0_DEVICE_ID);
  u16 status;
  status = XGpioPs_CfgInitialize(&my_Gpio, GPIO_Config, GPIO_Config->BaseAddr);
  if (status == XST_SUCCESS)
	xil_printf("XGpioPs configuration successful! \n\r");
  else
	xil_printf("XGpioPs configuration failed! \n\r");
  XGpioPs_SetDirectionPin(&my_Gpio, 47, 1); // board LED, output
  XGpioPs_SetOutputEnablePin(&my_Gpio, 47, 1);
  XGpioPs_SetDirectionPin(&my_Gpio, 51, 0); // USR button, input
  XGpioPs_SetDirectionPin(&my_Gpio, 54, 0); // EMIO pin, input
  XGpioPs_SetDirectionPin(&my_Gpio, 13, 1); // PMOD_D0 output for SW performance measurement
  XGpioPs_SetOutputEnablePin(&my_Gpio, 13, 1);
  status = XGpio_Initialize(&GPIO_4, XPAR_AXI_GPIO_4_DEVICE_ID); // bidirectional AXI_GPIO module
  if (status == XST_SUCCESS)
	xil_printf("AXI_GPIO configuration successful! \n\r");
  else
	xil_printf("AXI_GPIO configuration failed! \n\r");
  // Interrupt configuration:
  XScuGic_Config *Gic_Config;
  Gic_Config = XScuGic_LookupConfig(XPAR_PS7_SCUGIC_0_DEVICE_ID);
  status = XScuGic_CfgInitialize(&my_Gic, Gic_Config, Gic_Config->CpuBaseAddress);
  if (status == XST_SUCCESS)
    xil_printf("GIC configuration successful! \n\r");
  else
    xil_printf("GIC configuration failed! \n\r");
  Xil_ExceptionInit(); // initialize exception handlers on the processor
  Xil_ExceptionRegisterHandler(XIL_EXCEPTION_ID_INT, (Xil_ExceptionHandler)XScuGic_InterruptHandler, &my_Gic);
  status = XScuGic_Connect(&my_Gic, XPS_GPIO_INT_ID, (Xil_ExceptionHandler)USR_button_ISR, (void *)&my_Gic);
  if (status == XST_SUCCESS)
  	xil_printf("GPIO interrupt handler connection successful! \n\r");
  else
  	xil_printf("GPIO interrupt handler connection failed! \n\r");
  XGpioPs_SetIntrTypePin(&my_Gpio, 51, XGPIOPS_IRQ_TYPE_EDGE_RISING); // interrupt on rising edge
  XGpioPs_IntrClearPin(&my_Gpio, 51);  // clear any pending residual USR_button interrupts
  XGpioPs_IntrEnablePin(&my_Gpio, 51); // enable USR_button interrupt
  XScuGic_Enable(&my_Gic, XPS_GPIO_INT_ID); // enable GPIO interrupt (SPI: Shared Peripheral Interrupt)
  Xil_ExceptionEnable(); // enable interrupt handling
  XGpioPs_WritePin(&my_Gpio, 47, 1); // turn on the PS-ready indicator LED
}


/********************************************************************************************************
  2. USR_button_ISR: the user button Interrupt Service Routine.
  The function communicates with the PL fabric. It makes use of the static variable ctrl 
  and configures it to give the appropriate instructions to the design.
*********************************************************************************************************/
static void USR_button_ISR(void *CallBackReff)
{
  XGpioPs_IntrDisablePin(&my_Gpio, 51); // for debouncing the switch
  XGpioPs_IntrClearPin(&my_Gpio, 51);	// clear the interrupt flag
  XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED
  ctrl = 0x0020; 		  // reset=1
  Xil_Out16(ADDR0,ctrl);  // send from PS to FPGA via AXI interface
  xil_printf("\t\tFPGA design was reset!\n\r");
  sleep(1); 			  // for debouncing the switch
  ctrl = 0x0000; 		  // reset=0
  Xil_Out16(ADDR0,ctrl);
  XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the LED
  XGpioPs_IntrEnablePin(&my_Gpio, 51);
}


/********************************************************************************************************
  3. Zynq_crypt: the main function that communicates with the PL fabric and get it to execute 
  a "crypt" operation: encryption or decryption. The function makes use of the static variable ctrl 
  and configures it to give the appropriate instructions to the design.
  Function input parameters:
  text: pointer to u8 data-in array.
  key1, key2, key3, key4: four u32 parts of the key.
  IV1, IV2: two u32 parts of the IV (Initialization Vector).
  only_data: indicates the key period. 							1: new data, same key. 0: new data and new key.
  enc_dec: flag to the desired operation.						1: encryption. 0: decryption.
  op_mode: flag to the desired cryptographic mode of operation. 1: CBC. 0: ECB.
  first_block: flag for the CBC mode. 				 			1: first data block. 0: not first data block.
  new_IV: new IV flag.											1: new IV. 0: same IV.
  Function returns:
  result: pointer to u8 data out array.
*********************************************************************************************************/
void Zynq_crypt(const u8 * const text, const u32 key1, const u32 key2, const u32 key3, const u32 key4, const u32 IV1, const u32 IV2, const bool only_data, const bool enc_dec, const bool op_mode, const bool first_block, const bool new_IV, u8 * const result)
{
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

  if ((op_mode == 1) && (new_IV))
  {
	  // send IV:
	  Xil_Out32(ADDR3,IV1)				;
	  Xil_Out32(ADDR3 + ADDR_offset,IV2);
  }

  // set GPIO_4 to output and send data:
  XGpio_SetDataDirection(&GPIO_4,1,0x00000000);
  Xil_Out32(ADDR4			   ,d_in_1);
  Xil_Out32(ADDR4 + ADDR_offset,d_in_2);

  // ctrl setting:
  ctrl = ctrl ^ 0x0001;   // toggle bit 0, to issue a start command
  if (first_block == 1)
    ctrl = ctrl | 0x0002; // = ctrl|000010, turn on bit 1
  else
	ctrl = ctrl & 0xFFFD; // = ctrl&111101, turn off bit 1
  if (op_mode == 1)
    ctrl = ctrl | 0x0004; // = ctrl|000100, turn on bit 2
  else
	ctrl = ctrl & 0xFFFB; // = ctrl&111011, turn off bit 2
  if (enc_dec == 1)
    ctrl = ctrl | 0x0008; // = ctrl|001000, turn on bit 3
  else
	ctrl = ctrl & 0xFFF7; // = ctrl&110111, turn off bit 3
  if (only_data == 1)
    ctrl = ctrl | 0x0010; // = ctrl|010000, turn on bit 4
  else
	ctrl = ctrl & 0xFFEF; // = ctrl&101111, turn off bit 4

  Xil_Out16(ADDR0,ctrl);
  // can't send the start command before both key & data sent because key schedule will end before data has arrived,
  // and additional flags, and time to send them, will be needed.

  u16 finish;
  // set GPIO_4 to input and wait for data:
  XGpio_SetDataDirection(&GPIO_4,1,0xFFFFFFFF);
  do {
	  finish = XGpioPs_ReadPin(&my_Gpio, 54); // read from FPGA via EMIO interface (polling)
  } while ((finish ^ ctrl) & 0x0001); 		  // while LSB of finish != LSB of ctrl
  // in later version, the EMIO pin is connected to PL_ready, so the condition is: while (!PL_ready)

  // read data from PL via AXI bus:
  u32 d_out_1 = Xil_In32(ADDR4);
  u32 d_out_2 = Xil_In32(ADDR4 + ADDR_offset);

  // map two u32 d_out parts to u8-array text:
  result[0] = (u8)(d_out_1 >> 24);
  result[1] = (u8)(d_out_1 >> 16);
  result[2] = (u8)(d_out_1 >>  8);
  result[3] = (u8)(d_out_1      );
  result[4] = (u8)(d_out_2 >> 24);
  result[5] = (u8)(d_out_2 >> 16);
  result[6] = (u8)(d_out_2 >>  8);
  result[7] = (u8)(d_out_2      );
}


/********************************************************************************************************
  4. Zynq_crypt_simple: this function is very similar to Zynq_crypt, just more simple (less input parameters), 
  for use in the test vectors operations and in the PRNG.
  The key is given as one parameter, a pointer to u8 array - reflecting the way it's calculated in the test vectors files, 
  and mapping to four u32 key parts is done inside the function. Also the function lacks the only_data option and the CBC option.
  One can easily create different versions of this function for other kinds of tests.
*********************************************************************************************************/
void Zynq_crypt_simple(const u8 * const text, const u8 * const key, const bool enc_dec, u8 * const result)
{
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
  // set GPIO_4 to output and send data:
  XGpio_SetDataDirection(&GPIO_4,1,0x00000000);
  Xil_Out32(ADDR4			   ,d_in_1)	;
  Xil_Out32(ADDR4 + ADDR_offset,d_in_2)	;

  // ctrl setting:
  ctrl = ctrl ^ 0x0001;   // toggle bit 0, to issue a start command
  if (enc_dec == 1)
    ctrl = ctrl | 0x0008; // = ctrl|001000, turn on bit 3
  else
	ctrl = ctrl & 0xFFF7; // = ctrl&110111, turn off bit 3
  ctrl = ctrl & 0xFFE9;   // = ctrl&101001, turn off bits 4,2,1. only_data and CBC mode are inactive

  Xil_Out16(ADDR0,ctrl);
  // can't send the start command before both key & data sent because key schedule will end before data has arrived,
  // and additional flags, and time to send them, will be needed.

  u16 finish;
  // set GPIO_4 to input and wait for data:
  XGpio_SetDataDirection(&GPIO_4,1,0xFFFFFFFF);
  do {
	  finish = XGpioPs_ReadPin(&my_Gpio, 54); // read from FPGA via EMIO interface (polling)
  } while ((finish ^ ctrl) & 0x0001);		  // while LSB of finish != LSB of ctrl
  // in later version, the EMIO pin is connected to PL_ready, so the condition is: while (!PL_ready)

  // read data from PL via AXI bus:
  u32 d_out_1 = Xil_In32(ADDR4);
  u32 d_out_2 = Xil_In32(ADDR4 + ADDR_offset);
  
  // map two u32 d_out parts to u8-array text:
  result[0] = (u8)(d_out_1 >> 24);
  result[1] = (u8)(d_out_1 >> 16);
  result[2] = (u8)(d_out_1 >>  8);
  result[3] = (u8)(d_out_1      );
  result[4] = (u8)(d_out_2 >> 24);
  result[5] = (u8)(d_out_2 >> 16);
  result[6] = (u8)(d_out_2 >>  8);
  result[7] = (u8)(d_out_2      );
}


/********************************************************************************************************
  5. test_vectors: this function is essentially the original reference code bctestvectors.c code, 
  combined with encryption and decryption on HW, to test the HW implementation ECB results.
  If these results are different than the reference code results, an error massage appears.
  The original test includes a stage of 10^8 iterations, so it may take some time to be completed.
  We have added an option for shortened test, in which this stage was shortened into 10^6 iterations.
  We recommend to use this option if time is short.
*********************************************************************************************************/
void test_vectors()
{
  struct NESSIEstruct subkeys;
  bool valid_answer = 0;
  u8 answer;
  u8 key[KEYSIZEB];
  u8 plain[BLOCKSIZEB];
  u8 cipher[BLOCKSIZEB];
  u8 decrypted[BLOCKSIZEB];
  u32 i;
  int v, iterations;
  u8 Zynq_cipher[BLOCKSIZEB];
  u8 Zynq_decrypted[BLOCKSIZEB];

  do {
		xil_printf("For the short version test, please press 's'. For the full version test, please press 'f'. Warning: the full test may take a long time. \n\r");
		scanf(" %c", &answer);
		if ((answer == 's') || (answer == 'S'))
		{
			valid_answer = 1;
			iterations = 999999;
		}
		else if ((answer == 'f') || (answer == 'F'))
		{
			valid_answer = 1;
			iterations = 99999999;
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

  XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED

  xil_printf("Test vectors -- set 1\n");
  xil_printf("=====================\n\n");

  /* If key size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(KEYSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      key[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      xil_printf("Set 1, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        xil_printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
		   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        xil_printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");
			   
      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
	    Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      xil_printf("\n");
    }

  xil_printf("Test vectors -- set 2\n");
  xil_printf("=====================\n\n");

  /* If block size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(BLOCKSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      plain[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      xil_printf("Set 2, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        xil_printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
			   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        xil_printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");

      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      xil_printf("\n");
    }

  xil_printf("Test vectors -- set 3\n");
  xil_printf("=====================\n\n");

  for(v=0; v<256; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      xil_printf("Set 3, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        xil_printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);
	  Zynq_crypt_simple(Zynq_cipher, key, 0, Zynq_decrypted);
	  print_data("Zynq cipher", Zynq_cipher, BLOCKSIZEB);
	  print_data("Zynq decrypted", Zynq_decrypted, BLOCKSIZEB);
	  
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
   
	  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
        xil_printf("** Zynq decryption error: **\n"
               "   Decrypted ciphertext on Zynq is different than the plaintext!\n");

      for(i=0; i<99; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 100 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");
      for(i=0; i<900; i++)
	  {
        NESSIEencrypt(&subkeys, cipher, cipher);
		Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
	  }
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);
	  print_data("Iterated 1000 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      xil_printf("\n");
    }

  xil_printf("Test vectors -- set 4\n");
  xil_printf("=====================\n\n");

  for(v=0; v<4; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
	  Zynq_crypt_simple(plain, key, 1, Zynq_cipher);

      xil_printf("Set 4, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);

      for(i=0; i<iterations; i++)
        {
          memset(key, cipher[BLOCKSIZEB-1], KEYSIZEB);
          NESSIEkeysetup(key, &subkeys);
          NESSIEencrypt(&subkeys, cipher, cipher);
        }
	  if (iterations == 999999)
	    print_data("Iterated 10^6 times", cipher, BLOCKSIZEB);
	  else
		print_data("Iterated 10^8 times", cipher, BLOCKSIZEB);
	  for(i=0; i<iterations; i++)
        {
          memset(key, Zynq_cipher[BLOCKSIZEB-1], KEYSIZEB);
		  Zynq_crypt_simple(Zynq_cipher, key, 1, Zynq_cipher);
        }
	  if (iterations == 999999)
	    print_data("Iterated 10^6 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  else
		print_data("Iterated 10^8 times on Zynq", Zynq_cipher, BLOCKSIZEB);
	  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
        xil_printf("** Zynq encryption error: **\n"
               "   Ciphertext from Zynq is different than the reference code cipher!\n");

      xil_printf("\n");
    }

  xil_printf("\n\nEnd of test vectors\n");

  XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the PS-ready indicator LED
}


/********************************************************************************************************
  6. demonstration: this function is designed to demonstrate the hardware implementation correctness in a simple friendly way.
  It prompts the user for key and for plaintext string data, then processes the data block-by-block.
  Each block is encrypted and then decrypted, first by using the reference code, 
  then by using the Zynq hardware implementation.
  Since the function works block-by-block and switches between encryption and decryption, 
  only ECB mode can be used.
  For each block the plaintext, the reference code ciphertext, the reference code decrypted text, the Zynq ciphertext, 
  the Zynq decrypted text (all five in hexadecimal ASCII code) and the block number are printed on screen.
  Comparisons are made for each block between the reference code ciphertext and the Zynq ciphertext, 
  and between the plaintext and the Zynq decrypted text, 
  and also between the original characters string and a decrypted re-calculated string.
  If a comparison fails, an error massage appears.
  The demonstration calls the Zynq_crypt full version function, 
  and uses the only_data option whenever possible.
*********************************************************************************************************/
void demonstration()
{
  u32 key1, key2, key3, key4;
  u8 key[KEYSIZEB];
  struct NESSIEstruct subkeys;
  bool valid_answer, go = 1;
  u8 answer, data_string[MAX_LENGTH+1], decrypted_string[MAX_LENGTH+1], plain[BLOCKSIZEB], cipher[BLOCKSIZEB], decrypted[BLOCKSIZEB], Zynq_cipher[BLOCKSIZEB], Zynq_decrypted[BLOCKSIZEB];

  xil_printf("*************************************************************** \n\r");
  xil_printf("Secret key configuration: \nKHAZAD is using a 128-bit key (32 figures in hexadecimal base). \n");
  xil_printf("For your convenience, the key is entered in 4 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
  while (go)
  {
	  xil_printf("Please enter key part number 1 \n");
	  scanf("%x", &key1);
	  xil_printf("Please enter key part number 2 \n");
	  scanf("%x", &key2);
	  xil_printf("Please enter key part number 3 \n");
	  scanf("%x", &key3);
	  xil_printf("Please enter key part number 4 \n\r");
	  scanf("%x", &key4);
	  xil_printf("key= %08X%08X%08X%08X \n", key1, key2, key3, key4);
	  // map four u32 key parts to u8-array key:
	  key[0]  = (u8)(key1 >> 24);
	  key[1]  = (u8)(key1 >> 16);
	  key[2]  = (u8)(key1 >>  8);
	  key[3]  = (u8)(key1      );
	  key[4]  = (u8)(key2 >> 24);
	  key[5]  = (u8)(key2 >> 16);
	  key[6]  = (u8)(key2 >>  8);
	  key[7]  = (u8)(key2      );
	  key[8]  = (u8)(key3 >> 24);
	  key[9]  = (u8)(key3 >> 16);
	  key[10] = (u8)(key3 >>  8);
	  key[11] = (u8)(key3      );
	  key[12] = (u8)(key4 >> 24);
	  key[13] = (u8)(key4 >> 16);
	  key[14] = (u8)(key4 >>  8);
	  key[15] = (u8)(key4      );
	  NESSIEkeysetup(key, &subkeys);  // calculate the round keys

	  xil_printf("\nPlease enter data to encrypt (up to %d characters, including spaces) \n", MAX_LENGTH);
	  scanf(" %[^\r]s", data_string); // scanf format to allow reading spaces

	  XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED

	  u16 i = 0, j = 0, k = 0, block_num = 0;
	  while (data_string[i])
	  {
		  if (j < BLOCKSIZEB)
		  {
			  memset(plain+j, data_string[i], 1);
			  j++;
		  }

		  if ((j != BLOCKSIZEB) && !(data_string[i+1])) // residue exists
			  memset(plain+j, 0, BLOCKSIZEB-j); 		// zero padding

		  if (((j != BLOCKSIZEB) && !(data_string[i+1])) || (j == BLOCKSIZEB)) // need to encrypt
		  {
			  // reference code SW encryption & decryption:
			  NESSIEencrypt(&subkeys, plain, cipher);
			  NESSIEdecrypt(&subkeys, cipher, decrypted);
			  xil_printf("\n Text block number %u: \n", block_num+1);
			  print_data("plaintext", plain, BLOCKSIZEB);
			  print_data("SW ciphertext", cipher, BLOCKSIZEB);
			  print_data("SW decrypted text", decrypted, BLOCKSIZEB);

			  // Zynq HW encryption & decryption:
			  if (block_num == 0)
				Zynq_crypt(plain, key1, key2, key3, key4, 0, 0, 0, 1, 0, 0, 0, Zynq_cipher);   // first operation: only_data = 0. enc_dec = 1.
			  else
				Zynq_crypt(plain, key1, key2, key3, key4, 0, 0, 1, 1, 0, 0, 0, Zynq_cipher);   // not first operation: only_data = 1. enc_dec = 1.
			  Zynq_crypt(Zynq_cipher, key1, key2, key3, key4, 0, 0, 1, 0, 0, 0, 0, Zynq_decrypted); // not first operation: only_data = 1. enc_dec = 0.
			  print_data("HW ciphertext", Zynq_cipher, BLOCKSIZEB);
			  print_data("HW decrypted text", Zynq_decrypted, BLOCKSIZEB);

			  if(compare_blocks(cipher, Zynq_cipher, BLOCKSIZE) != 0)
			    xil_printf("** HW encryption error: **\n    Ciphertext from Zynq is different than the reference code cipher!\n");

			  if(compare_blocks(plain, Zynq_decrypted, BLOCKSIZE) != 0)
			    xil_printf("** HW decryption error: **\n    Decrypted ciphertext on Zynq is different than the plaintext!\n");

			  for (k = 0; k < j; k++)
				decrypted_string[block_num*BLOCKSIZEB + k] = Zynq_decrypted[k];
			  block_num++;
			  j = 0;
		  }
		  i++;
	  }

	  decrypted_string[i] = 0; // NULL character to end decrypted_string
	  xil_printf("\nThe original string is: %s \n\r", data_string);
	  xil_printf("The decrypted string from Zynq HW implementation is: %s \n\r", decrypted_string);
	  if (strcmp(data_string, decrypted_string) == 0)
	    xil_printf("Texts identical! \n\r");
	  else
	    xil_printf("ERROR: texts not identical! \n\r");

	  XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the PS-ready indicator LED

	  valid_answer = 0;
	  do {
		  xil_printf("Do you want to try this demonstration again? Please answer y/n \n\r");
		  scanf(" %c", &answer);
		  if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
			valid_answer = 1;
		  else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
		  {
			valid_answer = 1;
			go = 0;
			xil_printf("Going back to the main menu... \n\r");
		  }
		  else
			xil_printf("Not a valid input. \n\r");
	  } while (!valid_answer);
  }
  return;
}


/********************************************************************************************************
  7. HW_application: a simple practical encryption/decryption application. The calculations are done on hardware (the Zynq PL side).
  The user can choose between encryption and decryption, 
  then he's prompted for a key, for operation mode and for initialization vector (if CBC mode was chosen).
  For encryption, a plaintext string is entered, 
  and the ciphertext is calculated and printed on screen as hexadecimal figures.
  For decryption, a ciphertext hexadecimal figures string is entered, 
  and the plaintext is calculated and printed on screen as regular characters.
*********************************************************************************************************/
void HW_application()
{
  u32 key1 = 0, key2 = 0, key3 = 0, key4 = 0, IV1 = 0, IV2 = 0;
  bool enc_dec, only_data, op_mode, first_block, new_IV, valid_answer, key_entered, IV_entered, first_run = 1, CBC_first_run = 1, go = 1;
  u8 answer, data_in_string[MAX_LENGTH+1], cipher_in_string[2*MAX_LENGTH+1], block_in[BLOCKSIZEB], block_out[BLOCKSIZEB+1];
  char temp[2];

  xil_printf("*************************************************************** \n\r");
  while (go)
  {
	key_entered = 0;
	IV_entered = 0;
	valid_answer = 0;
	do {
		xil_printf("For encryption, please press 'e'.  For decryption, please press 'd'. \n\r");
		scanf(" %c", &answer);
		if ((answer == 'e') || (answer == 'E'))
		{
			valid_answer = 1;
			enc_dec = 1;  // =encryption
			xil_printf("Encryption mode \n\r");
		}
		else if ((answer == 'd') || (answer == 'D'))
		{
			valid_answer = 1;
			enc_dec = 0;  // =decryption
			xil_printf("Decryption mode \n\r");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

	valid_answer = 0;
	do {
		xil_printf("For ECB mode, please press '0'.  For CBC mode, please press '1'. \n\r");
		scanf(" %c", &answer);
		if (answer == '0')
		{
			valid_answer = 1;
			op_mode = 0;
			xil_printf("ECB mode \n\r");
		}
		else if (answer == '1')
		{
			valid_answer = 1;
			op_mode = 1;
			xil_printf("CBC mode \n\r");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

	if (!first_run)
	{
		valid_answer = 0;
		do {
			xil_printf("Do you want to enter a new key? Please answer y/n \n\r");
			scanf(" %c", &answer);
			if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
				valid_answer = 1;
			else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
				valid_answer = 1;
			else
				xil_printf("Not a valid input. \n\r");
		} while (!valid_answer);
	}

	if ((first_run) || ((!first_run) && ((answer == 'y') || (answer == 'Y') || (answer == '1'))))
	{
		xil_printf("Secret key configuration: \nKHAZAD is using a 128-bit key (32 figures in hexadecimal base). \n");
		xil_printf("For your convenience, the key is entered in 4 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
		xil_printf("Please enter key part number 1 \n");
		scanf("%x", &key1);
		xil_printf("Please enter key part number 2 \n");
		scanf("%x", &key2);
		xil_printf("Please enter key part number 3 \n");
		scanf("%x", &key3);
		xil_printf("Please enter key part number 4 \n\r");
		scanf("%x", &key4);
		key_entered = 1;
	}
	xil_printf("key= %08X%08X%08X%08X \n\r", key1, key2, key3, key4);

	if ((!CBC_first_run) && (op_mode == 1))
	{
		valid_answer = 0;
		do {
			xil_printf("Do you want to enter a new IV? Please answer y/n \n\r");
			scanf(" %c", &answer);
			if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
				valid_answer = 1;
			else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
				valid_answer = 1;
			else
				xil_printf("Not a valid input. \n\r");
		} while (!valid_answer);
	}

	if ((op_mode == 1) && ((CBC_first_run) || ((!CBC_first_run) && ((answer == 'y') || (answer == 'Y') || (answer == '1')))))
	{
		xil_printf("Initialization Vector: \n");
		xil_printf("For your convenience, the IV is entered in 2 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
		xil_printf("Please enter IV part number 1 \n");
		scanf("%x", &IV1);
		xil_printf("Please enter IV part number 2 \n");
		scanf("%x", &IV2);
		IV_entered = 1;
	}
	
	if (op_mode == 1)
		xil_printf("IV= %08X%08X \n", IV1, IV2);

	u16 i = 0;
	if (enc_dec == 1)  // plaintext input: use the input as is
	{
		xil_printf("\nPlease enter data to encrypt (up to %d characters, including spaces) \n", MAX_LENGTH);
		scanf(" %[^\r]s", data_in_string);  // scanf format to allow reading spaces
		xil_printf("\n\t the ciphertext: \n");
	}
	else  			   // ciphertext input: convert the input from hexadecimal figures string to characters string
	{
		xil_printf("\nPlease enter data to decrypt - a sequence of hexadecimal figures pairs (up to %d characters) \n", 2*MAX_LENGTH);
		scanf("%s", cipher_in_string);
		while (cipher_in_string[i])
		{
			temp[0] = cipher_in_string[i];	// each hexadecimal figures pair is the ASCII code of one character
			temp[1] = cipher_in_string[i+1];
			data_in_string[i/2] = (u8)strtol(temp, NULL, 16);	// convert hexadecimal string to long int to u8
			i+=2;
		}
		data_in_string[i/2] = 0;  // NULL character to end the string
		xil_printf("\n\t the plaintext: \n");
	}

	XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED

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
			memset(block_in+j, 0, BLOCKSIZEB-j); 		 // zero padding

		if (((j != BLOCKSIZEB) && !(data_in_string[i+1])) || (j == BLOCKSIZEB)) // need to encrypt/decrypt
		{
			if (block_num == 0)
				first_block = 1;
			else
				first_block = 0;

			if ((block_num == 0) && (key_entered == 1))
				only_data = 0;
			else
				only_data = 1;

			if ((block_num == 0) && (IV_entered == 1))
				new_IV = 1;
			else
				new_IV = 0;

			Zynq_crypt(block_in, key1, key2, key3, key4, IV1, IV2, only_data, enc_dec, op_mode, first_block, new_IV, block_out);
			if (enc_dec == 1)
				for (k=0; k < BLOCKSIZEB; k++) // ciphertext output: print as hexadecimal figures
				{
					putchar(hex[(block_out[k]>>4)&0xF]);
					putchar(hex[(block_out[k]   )&0xF]);
				}
			else
				xil_printf("%s", block_out);       // plaintext output: print as characters

			block_num++;
			j = 0;
		}
		i++;
	}

	first_run = 0;
	if (op_mode == 1)
	  CBC_first_run = 0;

	XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the PS-ready indicator LED

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
			xil_printf("Going back to the main menu... \n\r");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);
  }
}


/********************************************************************************************************
  8. NESSIEencrypt_CBC: this function wraps the reference code "NESSIEencrypt" function with the 
  necessary commands to execute encryption in CBC mode.
*********************************************************************************************************/
void NESSIEencrypt_CBC(const struct NESSIEstruct * const structpointer, const u8 * const plaintext, u8 * const CBC_Xor, u8 * const ciphertext)
{
	u8 CBC_input[BLOCKSIZEB];
	u16 i = 0;
	// XOR:
	for (i=0; i < BLOCKSIZEB; i++)
		CBC_input[i] = plaintext[i] ^ CBC_Xor[i];

	// encryption:
	NESSIEencrypt(structpointer, CBC_input, ciphertext);

	// update the XOR factor:
	for (i=0; i < BLOCKSIZEB; i++)
		CBC_Xor[i] = ciphertext[i];
}


/********************************************************************************************************
  9. NESSIEdecrypt_CBC: this function wraps the reference code "NESSIEdecrypt" function with the 
  necessary commands to execute decryption in CBC mode.
*********************************************************************************************************/
void NESSIEdecrypt_CBC(const struct NESSIEstruct * const structpointer, const u8 * const ciphertext, u8 * const CBC_Xor, u8 * const plaintext)
{
	u8 CBC_output[BLOCKSIZEB];
	// decryption:
	NESSIEdecrypt(structpointer, ciphertext, CBC_output);

	u16 i = 0;
	// XOR, update the XOR factor:
	for (i=0; i < BLOCKSIZEB; i++)
	{
		plaintext[i] = CBC_output[i] ^ CBC_Xor[i];
		CBC_Xor[i] = ciphertext[i];
	}
}


/********************************************************************************************************
  10. SW_application: a simple practical encryption/decryption application. The calculations are done on software (the Zynq PS side).
  The application is identical to the HW_application:
  The user can choose between encryption and decryption, 
  then he's prompted for a key, for operation mode and for initialization vector (if CBC mode was chosen).
  For encryption, a plaintext string is entered, 
  and the ciphertext is calculated and printed on screen as hexadecimal figures.
  For decryption, a ciphertext hexadecimal figures string is entered, 
  and the plaintext is calculated and printed on screen as regular characters.
*********************************************************************************************************/
void SW_application()
{
  u32 key1 = 0, key2 = 0, key3 = 0, key4 = 0, IV1 = 0, IV2 = 0;
  u8 key[KEYSIZEB], CBC_Xor[BLOCKSIZEB];
  struct NESSIEstruct subkeys;
  bool enc_dec, op_mode, valid_answer, first_run = 1, CBC_first_run = 1, go = 1;
  u8 answer, data_in_string[MAX_LENGTH+1], cipher_in_string[2*MAX_LENGTH+1], block_in[BLOCKSIZEB], block_out[BLOCKSIZEB+1];
  char temp[2];

  xil_printf("*************************************************************** \n\r");
  while (go)
  {
	valid_answer = 0;
	do {
		xil_printf("For encryption, please press 'e'.  For decryption, please press 'd'. \n\r");
		scanf(" %c", &answer);
		if ((answer == 'e') || (answer == 'E'))
		{
			valid_answer = 1;
			enc_dec = 1;  // =encryption
			xil_printf("Encryption mode \n\r");
		}
		else if ((answer == 'd') || (answer == 'D'))
		{
			valid_answer = 1;
			enc_dec = 0;  // =decryption
			xil_printf("Decryption mode \n\r");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

	  valid_answer = 0;
	  do {
		  xil_printf("For ECB mode, please press '0'.  For CBC mode, please press '1'. \n\r");
		  scanf(" %c", &answer);
		  if (answer == '0')
		  {
			valid_answer = 1;
			op_mode = 0;
			xil_printf("ECB mode \n\r");
		  }
		  else if (answer == '1')
		  {
			valid_answer = 1;
			op_mode = 1;
			xil_printf("CBC mode \n\r");
		  }
		  else
			xil_printf("Not a valid input. \n\r");
	  } while (!valid_answer);

	if (!first_run)
	{
		valid_answer = 0;
		do {
			xil_printf("Do you want to enter a new key? Please answer y/n \n\r");
			scanf(" %c", &answer);
			if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
				valid_answer = 1;
			else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
				valid_answer = 1;
			else
				xil_printf("Not a valid input. \n\r");
		} while (!valid_answer);
	}

	if ((first_run) || ((!first_run) && ((answer == 'y') || (answer == 'Y') || (answer == '1'))))
	{
		xil_printf("Secret key configuration: \nKHAZAD is using a 128-bit key (32 figures in hexadecimal base). \n");
		xil_printf("For your convenience, the key is entered in 4 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
		xil_printf("Please enter key part number 1 \n");
		scanf("%x", &key1);
		xil_printf("Please enter key part number 2 \n");
		scanf("%x", &key2);
		xil_printf("Please enter key part number 3 \n");
		scanf("%x", &key3);
		xil_printf("Please enter key part number 4 \n\r");
		scanf("%x", &key4);
		// map four u32 key parts to u8-array key:
		key[0]  = (u8)(key1 >> 24);
		key[1]  = (u8)(key1 >> 16);
		key[2]  = (u8)(key1 >>  8);
		key[3]  = (u8)(key1      );
		key[4]  = (u8)(key2 >> 24);
		key[5]  = (u8)(key2 >> 16);
		key[6]  = (u8)(key2 >>  8);
		key[7]  = (u8)(key2      );
		key[8]  = (u8)(key3 >> 24);
		key[9]  = (u8)(key3 >> 16);
		key[10] = (u8)(key3 >>  8);
		key[11] = (u8)(key3      );
		key[12] = (u8)(key4 >> 24);
		key[13] = (u8)(key4 >> 16);
		key[14] = (u8)(key4 >>  8);
		key[15] = (u8)(key4      );
		NESSIEkeysetup(key, &subkeys);  // calculate the round keys
	}
	xil_printf("key= %08X%08X%08X%08X \n\r", key1, key2, key3, key4);

	if ((!CBC_first_run) && (op_mode == 1))
	{
		valid_answer = 0;
		do {
			xil_printf("Do you want to enter a new IV? Please answer y/n \n\r");
			scanf(" %c", &answer);
			if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
				valid_answer = 1;
			else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
				valid_answer = 1;
			else
				xil_printf("Not a valid input. \n\r");
		} while (!valid_answer);
	}

	if ((op_mode == 1) && ((CBC_first_run) || ((!CBC_first_run) && ((answer == 'y') || (answer == 'Y') || (answer == '1')))))
	{
		xil_printf("Initialization Vector: \n");
		xil_printf("For your convenience, the IV is entered in 2 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
		xil_printf("Please enter IV part number 1 \n");
		scanf("%x", &IV1);
		xil_printf("Please enter IV part number 2 \n");
		scanf("%x", &IV2);
	}

	if (op_mode == 1)
	{
		xil_printf("IV= %08X%08X \n", IV1, IV2);
		// map two u32 IV parts to u8-array:
		CBC_Xor[0] = (u8)(IV1 >> 24);
		CBC_Xor[1] = (u8)(IV1 >> 16);
		CBC_Xor[2] = (u8)(IV1 >>  8);
		CBC_Xor[3] = (u8)(IV1      );
		CBC_Xor[4] = (u8)(IV2 >> 24);
		CBC_Xor[5] = (u8)(IV2 >> 16);
		CBC_Xor[6] = (u8)(IV2 >>  8);
		CBC_Xor[7] = (u8)(IV2      );
	}

	u16 i = 0;
	if (enc_dec == 1)  // plaintext input: use the input as is
	{
		xil_printf("\nPlease enter data to encrypt (up to %d characters, including spaces) \n", MAX_LENGTH);
		scanf(" %[^\r]s", data_in_string);  // scanf format to allow reading spaces
		xil_printf("\n\t the ciphertext: \n");
	}
	else  			   // ciphertext input: convert the input from hexadecimal figures string to characters string
	{
		xil_printf("\nPlease enter data to decrypt - a sequence of hexadecimal figures pairs (up to %d characters) \n", 2*MAX_LENGTH);
		scanf("%s", cipher_in_string);
		while (cipher_in_string[i])
		{
			temp[0] = cipher_in_string[i];	// each hexadecimal figures pair is the ASCII code of one character
			temp[1] = cipher_in_string[i+1];
			data_in_string[i/2] = (u8)strtol(temp, NULL, 16);	// convert hexadecimal string to long int to u8
			i+=2;
		}
		data_in_string[i/2] = 0;  // NULL character to end the string
		xil_printf("\n\t the plaintext: \n");
	}

	XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED

	block_out[BLOCKSIZEB] = 0;    // NULL character to end the string
	i = 0;
	u16 j = 0, k = 0;
	while (data_in_string[i])
	{
		if (j < BLOCKSIZEB)
		{
			memset(block_in+j, data_in_string[i], 1);
			j++;
		}

		if ((j != BLOCKSIZEB) && !(data_in_string[i+1])) // residue exists
			memset(block_in+j, 0, BLOCKSIZEB-j); 		 // zero padding

		if (((j != BLOCKSIZEB) && !(data_in_string[i+1])) || (j == BLOCKSIZEB)) // need to encrypt/decrypt
		{
			if (enc_dec == 1)
			{
				if (op_mode == 0)
					NESSIEencrypt(&subkeys, block_in, block_out);  				// ECB encryption
				else
					NESSIEencrypt_CBC(&subkeys, block_in, CBC_Xor, block_out);  // CBC encryption
				for (k=0; k < BLOCKSIZEB; k++) 			// ciphertext output: print as hexadecimal figures
				{
					putchar(hex[(block_out[k]>>4)&0xF]);
					putchar(hex[(block_out[k]   )&0xF]);
				}					
			}
			else
			{
				if (op_mode == 0)
					NESSIEdecrypt(&subkeys, block_in, block_out);  				// ECB decryption
				else
					NESSIEdecrypt_CBC(&subkeys, block_in, CBC_Xor, block_out);  // CBC decryption
				xil_printf("%s", block_out);    		  	// plaintext output: print as characters
			}

			j = 0;
		}
		i++;
	}

	first_run = 0;
	if (op_mode == 1)
	  CBC_first_run = 0;

	XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the PS-ready indicator LED

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
			xil_printf("Going back to the main menu... \n\r");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);
  }
}


/********************************************************************************************************
  11. CBC_MAC (Message Authentication Code): 
  this function is similar to the HW_application function, and generates a basic CBC-MAC.
*********************************************************************************************************/
void CBC_MAC()
{
  u32 key1 = 0, key2 = 0, key3 = 0, key4 = 0, IV1 = 0, IV2 = 0;
  bool only_data, first_block, new_IV, valid_answer, key_entered, first_run = 1, go = 1;
  u8 answer, data_in_string[MAX_LENGTH+1], block_in[BLOCKSIZEB], block_out[BLOCKSIZEB];

  xil_printf("*************************************************************** \n\r");
  xil_printf("CBC-MAC generator \n");
  xil_printf("using the KHAZAD algorithm \n\r");
  while (go)
  {
	key_entered = 0;

	if (!first_run)
	{
		valid_answer = 0;
		do {
			xil_printf("Do you want to enter a new key? Please answer y/n \n\r");
			scanf(" %c", &answer);
			if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
				valid_answer = 1;
			else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
				valid_answer = 1;
			else
				xil_printf("Not a valid input. \n\r");
		} while (!valid_answer);
	}

	if ((first_run) || ((!first_run) && ((answer == 'y') || (answer == 'Y') || (answer == '1'))))
	{
		xil_printf("Secret key configuration: \nKHAZAD is using a 128-bit key (32 figures in hexadecimal base). \n");
		xil_printf("For your convenience, the key is entered in 4 parts, each one up to 8 figures in hexadecimal base \n(leading zeros will be added). \n\r");
		xil_printf("Please enter key part number 1 \n");
		scanf("%x", &key1);
		xil_printf("Please enter key part number 2 \n");
		scanf("%x", &key2);
		xil_printf("Please enter key part number 3 \n");
		scanf("%x", &key3);
		xil_printf("Please enter key part number 4 \n\r");
		scanf("%x", &key4);
		key_entered = 1;
	}
	xil_printf("key= %08X%08X%08X%08X \n\r", key1, key2, key3, key4);
	xil_printf("IV= %08X%08X \n", IV1, IV2);

	xil_printf("\nPlease enter a message (up to %d characters, including spaces) \n", MAX_LENGTH);
	scanf(" %[^\r]s", data_in_string);  // scanf format to allow reading spaces

	XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED

	u16 i = 0, j = 0, k = 0, block_num = 0;
	while (data_in_string[i])
	{
		if (j < BLOCKSIZEB)
		{
			memset(block_in+j, data_in_string[i], 1);
			j++;
		}

		if ((j != BLOCKSIZEB) && !(data_in_string[i+1])) // residue exists
			memset(block_in+j, 0, BLOCKSIZEB-j); 		 // zero padding

		if (((j != BLOCKSIZEB) && !(data_in_string[i+1])) || (j == BLOCKSIZEB)) // need to encrypt
		{
			if (block_num == 0)
				first_block = 1;
			else
				first_block = 0;

			if ((block_num == 0) && (key_entered == 1))
				only_data = 0;
			else
				only_data = 1;

			if ((block_num == 0) && (first_run == 1))
				new_IV = 1;
			else
				new_IV = 0;

			Zynq_crypt(block_in, key1, key2, key3, key4, IV1, IV2, only_data, 1, 1, first_block, new_IV, block_out); // enc_dec=1, op_mode=1

			block_num++;
			j = 0;
		}
		i++;
	}

	xil_printf("\n\t CBC-MAC: \n");
	for (k=0; k < BLOCKSIZEB; k++) // print as hexadecimal figures
	{
		putchar(hex[(block_out[k]>>4)&0xF]);
		putchar(hex[(block_out[k]   )&0xF]);
	}

	first_run = 0;

	XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the PS-ready indicator LED

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
			xil_printf("Going back to the main menu... \n\r");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);
  }
}


/********************************************************************************************************
  12. PRNG (Pseudo-Random Number Generator): 
  this function makes use of the KHAZAD algorithm HW implementation to generate 64-bit cryptographically secure pseudo-random numbers.
  It implements the CTR mode of operation principle: 
  the first half of the input data block is a fixed nonce value, and the second half is a running counter.
  It uses a fixed key value, and the Zynq_crypt_simple function.
  The nonce and the key were chosen randomly, and one can easily replace them with new values.
  For a given set of values, the PRNG is deterministic.
*********************************************************************************************************/
void PRNG(u8 * const result)
{
	u8 input[BLOCKSIZEB];
	u16 i;
	// get NONCE in the first half of u8-array input:
    for (i=0; i < BLOCKSIZEB/2; i++)
	  input[i] = nonce[i];
	// map u32 counter to the second half of u8-array input:
    input[4] = (u8)(counter >> 24);
    input[5] = (u8)(counter >> 16);
    input[6] = (u8)(counter >>  8);
    input[7] = (u8)(counter      );
	Zynq_crypt_simple(input, PRNG_key, 1, result);
	counter++;
}


/********************************************************************************************************
  13. random_vectors_test: compares HW implementation results to SW implementation results for random vectors.
  This test is particularly important for CBC mode, for which there are no given test vectors results.
  The random vectors are generated by the PRNG function, which is using the CTR mode principle 
  (using KHAZAD in a non-feedback state, which was already tested by the ECB mode).
  This PRNG give better randomness than C rand() function, which is usually a Linear Congruential Generator (LCG).
  Also, rand() maximum output is RAND_MAX, which is library-dependent, and in our case is 31-bit long.
  PRNG yields a 64-bit long random number.
*********************************************************************************************************/
void random_vectors_test()
{
	u32 key1, key2, key3, key4, IV1, IV2;
	int keys_num, messages_num, errors = 0;
	u8 key[KEYSIZEB], IV[BLOCKSIZEB], CBC_Xor[BLOCKSIZEB], plain[BLOCKS_NUM][BLOCKSIZEB], cipher[BLOCKS_NUM][BLOCKSIZEB], decrypted[BLOCKS_NUM][BLOCKSIZEB], Zynq_cipher[BLOCKS_NUM][BLOCKSIZEB], Zynq_decrypted[BLOCKS_NUM][BLOCKSIZEB], answer;
	struct NESSIEstruct subkeys;
	bool op_mode, only_data, first_block, new_IV = 0, valid_answer;

	xil_printf("*************************************************************** \n\r");
	xil_printf("Please enter a number of random keys to use \n\r");
	scanf("%u", &keys_num);
	xil_printf("Please enter a number of random messages to test for each key. Each message consists of %u data blocks. \n\r", BLOCKS_NUM);
	scanf("%u", &messages_num);

	valid_answer = 0;
	do {
		xil_printf("For ECB mode, please press '0'.  For CBC mode, please press '1'. \n\r");
		scanf(" %c", &answer);
		if (answer == '0')
		{
			valid_answer = 1;
			op_mode = 0;
			xil_printf("ECB mode \n");
		}
		else if (answer == '1')
		{
			valid_answer = 1;
			op_mode = 1;
			xil_printf("CBC mode \n");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

	XGpioPs_WritePin(&my_Gpio, 47, 0);	// turn off the PS-ready indicator LED

	int i, j, k, m;
	for (i=0; i < keys_num; i++)
	{
		// random key:
		PRNG(key);
		PRNG(&key[KEYSIZEB/2]);

		// map u8-array key to four u32 key parts:
		key1 =
			((u32)key[0] << 24) ^
			((u32)key[1] << 16) ^
			((u32)key[2] <<  8) ^
			((u32)key[3]      );

		key2 =
			((u32)key[4] << 24) ^
			((u32)key[5] << 16) ^
			((u32)key[6] <<  8) ^
			((u32)key[7]      );

		key3 =
			((u32)key[ 8] << 24) ^
			((u32)key[ 9] << 16) ^
			((u32)key[10] <<  8) ^
			((u32)key[11]      );

		key4 =
			((u32)key[12] << 24) ^
			((u32)key[13] << 16) ^
			((u32)key[14] <<  8) ^
			((u32)key[15]      );

		xil_printf("\n\n\tkey #%u = %08X%08X%08X%08X \n\r", i+1, key1, key2, key3, key4);

		NESSIEkeysetup(key, &subkeys);  // SW implementation round keys calculation

		if (op_mode == 1)
		{
			// random IV:
			PRNG(IV);

			// map u8-array IV to two u32 IV parts:
			IV1 =
				((u32)IV[0] << 24) ^
				((u32)IV[1] << 16) ^
				((u32)IV[2] <<  8) ^
				((u32)IV[3]      );

			IV2 =
				((u32)IV[4] << 24) ^
				((u32)IV[5] << 16) ^
				((u32)IV[6] <<  8) ^
				((u32)IV[7]      );

			new_IV = 1;

			printf("\tIV #%u = %08X%08X", i+1, IV1, IV2);
		}

		for (j=0; j < messages_num; j++)
		{
			printf("\n\n\tmessage #%u: \n\n\r", j+1);
			printf("plaintext: \n\r");
			for (k=0; k < BLOCKS_NUM; k++)
			{
				// random data block:
				PRNG(plain[k]);
				for (m=0; m < BLOCKSIZEB; m++) 		// print as hexadecimal figures
				{
					putchar(hex[(plain[k][m]>>4)&0xF]);
					putchar(hex[(plain[k][m]   )&0xF]);
				}
				printf("  ");
			}

			only_data = 0;		// for each message re-send key to HW, because PRNG() has changed it

			printf("\n\nSW ciphertext: \n\r");

			if (op_mode == 0)
				for (k=0; k < BLOCKS_NUM; k++)
				{
					NESSIEencrypt(&subkeys, plain[k], cipher[k]);  				// ECB encryption
					for (m=0; m < BLOCKSIZEB; m++)
					{
						putchar(hex[(cipher[k][m]>>4)&0xF]);
						putchar(hex[(cipher[k][m]   )&0xF]);
					}
					printf("  ");
				}
			else
			{
				for (m=0; m < BLOCKSIZEB; m++) // for each message reset CBC_Xor in SW, because last CBC opration has changed it
					CBC_Xor[m] = IV[m];
				for (k=0; k < BLOCKS_NUM; k++)
				{
					NESSIEencrypt_CBC(&subkeys, plain[k], CBC_Xor, cipher[k]);  // CBC encryption
					for (m=0; m < BLOCKSIZEB; m++)
					{
						putchar(hex[(cipher[k][m]>>4)&0xF]);
						putchar(hex[(cipher[k][m]   )&0xF]);
					}
					printf("  ");
				}
			}

			printf("\n\nSW decrypted text: \n\r");

			if (op_mode == 0)
				for (k=0; k < BLOCKS_NUM; k++)
				{
					NESSIEdecrypt(&subkeys, cipher[k], decrypted[k]);  			// ECB decryption
					for (m=0; m < BLOCKSIZEB; m++)
					{
						putchar(hex[(decrypted[k][m]>>4)&0xF]);
						putchar(hex[(decrypted[k][m]   )&0xF]);
					}
					printf("  ");
				}
			else
			{
				for (m=0; m < BLOCKSIZEB; m++) // reset CBC_Xor because last CBC opration has changed it
					CBC_Xor[m] = IV[m];
				for (k=0; k < BLOCKS_NUM; k++)
				{
					NESSIEdecrypt_CBC(&subkeys, cipher[k], CBC_Xor, decrypted[k]); // CBC decryption
					for (m=0; m < BLOCKSIZEB; m++)
					{
						putchar(hex[(decrypted[k][m]>>4)&0xF]);
						putchar(hex[(decrypted[k][m]   )&0xF]);
					}
					printf("  ");
				}
			}

			printf("\n\nHW ciphertext: \n\r");
			for (k=0; k < BLOCKS_NUM; k++)
			{
				if (k == 0)
					first_block = 1;
				else
					first_block = 0;

				if (k == 1)
				{
					new_IV = 0;
					only_data = 1;
				}

				Zynq_crypt(plain[k], key1, key2, key3, key4, IV1, IV2, only_data, 1, op_mode, first_block, new_IV, Zynq_cipher[k]); //enc_dec=1
				for (m=0; m < BLOCKSIZEB; m++)
				{
					putchar(hex[(Zynq_cipher[k][m]>>4)&0xF]);
					putchar(hex[(Zynq_cipher[k][m]   )&0xF]);
				}
				printf("  ");
			}

			printf("\n\nHW decrypted text: \n\r");
			for (k=0; k < BLOCKS_NUM; k++)
			{
				if (k == 0)
					first_block = 1;
				else
					first_block = 0;

				Zynq_crypt(Zynq_cipher[k], key1, key2, key3, key4, IV1, IV2, only_data, 0, op_mode, first_block, new_IV, Zynq_decrypted[k]); //enc_dec=0
				for (m=0; m < BLOCKSIZEB; m++)
				{
					putchar(hex[(Zynq_decrypted[k][m]>>4)&0xF]);
					putchar(hex[(Zynq_decrypted[k][m]   )&0xF]);
				}
				printf("  ");
			}

			printf("\n");
			for (k=0; k < BLOCKS_NUM; k++)
			{
				if(compare_blocks(plain[k], decrypted[k], BLOCKSIZE) != 0)
				{
					printf("** SW error on block %u: Decrypted text is different than the plaintext!\n", k+1);
					errors++;
				}

				if(compare_blocks(plain[k], Zynq_decrypted[k], BLOCKSIZE) != 0)
				{
					printf("** HW error on block %u: Decrypted text is different than the plaintext!\n", k+1);
					errors++;
				}

				if(compare_blocks(cipher[k], Zynq_cipher[k], BLOCKSIZE) != 0)
				{
					printf("** Implementation error on block %u: HW ciphertext is different than SW ciphertext!\n", k+1);
					errors++;
				}
			}
		}
	}

	printf("\n\nNumber of data blocks tested: %u \n", keys_num * messages_num * BLOCKS_NUM);
	if (errors == 0)
		printf("All blocks processed successfully! \n");
	else
		printf("Number of errors detected: %u \n", errors);

	XGpioPs_WritePin(&my_Gpio, 47, 1);	// turn on the PS-ready indicator LED
}


/********************************************************************************************************
  14. PRNG_application: this function prints on screen a 64-bit cryptographically secure pseudo-random number.
  The seed data is also printed, to enable reproducing of the random stream.
  For cryptographic purposes, this data should be kept secret, and not used twice.
*********************************************************************************************************/
void PRNG_application()
{
	u8 result[BLOCKSIZEB], answer;
	bool valid_answer, go = 1;
	u16 i;

	xil_printf("*************************************************************** \n\r");
	xil_printf("64-bit CSPRNG: Cryptographically Secure Pseudo-Random Number Generator \n");
	xil_printf("using the KHAZAD algorithm in CTR mode \n\r");
	xil_printf("CSPRNG seed: \n");
	print_data("Nonce", nonce, BLOCKSIZEB/2);
	print_data("Key", PRNG_key, KEYSIZEB);
	xil_printf("\n\r");
	do {
		PRNG(result);
		for (i=0; i < BLOCKSIZEB; i++) // print as hexadecimal figures
		{
			putchar(hex[(result[i]>>4)&0xF]);
			putchar(hex[(result[i]   )&0xF]);
		}
		valid_answer = 0;
		do {
			printf("\n\nDo you want to generate another random number? Please answer y/n \n\r");
			scanf(" %c", &answer);
			if ((answer == 'y') || (answer == 'Y') || (answer == '1'))
				valid_answer = 1;
			else if ((answer == 'n') || (answer == 'N') || (answer == '0'))
			{
				valid_answer = 1;
				go = 0;
				xil_printf("Going back to the main menu... \n\r");
			}
			else
				xil_printf("Not a valid input. \n\r");
		} while (!valid_answer);
	} while (go);
}


/********************************************************************************************************
  15. print_data: prints a given string "str", then "=", then the ASCII code in hexadecimal figures of 
  each element in a given u8 array.
  From the reference code bctestvectors.c file.
*********************************************************************************************************/
void print_data(char *str, u8 *val, int len) // from reference code bctestvectors.c file
{
  int i;

  xil_printf("%25s=", str);
  for(i=0; i<len; i++)
    {
      putchar(hex[(val[i]>>4)&0xF]);
      putchar(hex[(val[i]   )&0xF]);
    }
  putchar('\n');
}


/********************************************************************************************************
  16. compare_blocks: compares two u8 strings with the same given length.
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
  17. about: prints information about this project.
  When the design operates on bare-metal, there is no filesystem, so no text file can be used.
*********************************************************************************************************/
void about()
{
	xil_printf("*********************************************************************************************************\n");
	xil_printf("*********************************************************************************************************\n");
	xil_printf("Zynq-7000 based Implementation of the KHAZAD Block Cipher\n");
	xil_printf("Yossef Shitzer & Efraim Wasserman\n");
	xil_printf("Jerusalem College of Technology - Lev Academic Center (JCT)\n");
	xil_printf("Department of electrical and electronic engineering\n");
	xil_printf("2018\n\r");

	xil_printf("''The KHAZAD Legacy-Level Block Cipher'' is an involutional block cipher designed by Paulo S.L.M. Barreto and Vincent Rijmen.\n");
	xil_printf("It has a substitution-permutation network (SPN) structure, \n");
	xil_printf("and it uses a 128-bit key, operates on 64-bit data blocks, and comprises 8 rounds.\n");
	xil_printf("An interesting feature of the algorithm is that the same round function is used for both the key schedule part and for encryption/decryption.\n");
	xil_printf("The algorithm has been submitted as a candidate for the first open NESSIE workshop in 2000.\n");
	xil_printf("This first version now considered obsolete. For phase 2 of NESSIE, a modified version has been submitted, \n");
	xil_printf("named ''Khazad-tweak'', and has been accepted as NESSIE finalist.\n");
	xil_printf("This version can be found here:\n");
	xil_printf("https://www.cosic.esat.kuleuven.be/nessie/tweaks.html \n\r");

	xil_printf("The algorithm developers wrote: \n");
	xil_printf("''Khazad is named after Khazad-dum, ''the Mansion of the Khazad'', which in the tongue of the Dwarves is \n");
	xil_printf("the name of the great realm and city of Dwarrowdelf, of the haunted mithril mines in Moria, the Black Chasm.\n");
	xil_printf("But all this should be quite obvious – unless you haven't read J.R.R. Tolkien's ''The Lord of the Rings'', of course :-)  ''\n\r");

	xil_printf("This implementation of KHAZAD uses the MicroZed 7010 development board by Avnet Inc., \n");
	xil_printf("which is based on a Xilinx Zynq-7010 All Programmable SoC.\n");
	xil_printf("The Zynq Z-7010 device integrates a dual-core ARM Cortex A9 processor with an Artix-7 FPGA.\n");
	xil_printf("This new concept allows many interesting and exciting possibilities.\n");
	xil_printf("In this project, implementation was done in two ways: software and hardware.\n");
	xil_printf("In the software implementation, all the calculations are done using the Zynq processing system (PS).\n");
	xil_printf("In the hardware implementation, the PS is used mainly for dealing with user input & output operations, \n");
	xil_printf("and the programmable logic (PL) is used for implementing the algorithm and making the calculations.\n");
	xil_printf("Both implementations include the basic ECB (Electronic Codebook) mode and the more complex CBC (Cipher Block Chaining) mode.\n");
	xil_printf("The CBC mode is also used to generate basic CBC-MAC (Message Authentication Code).\n");
	xil_printf("In addition, a CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) was created, using the CTR mode principle.\n\r");

	xil_printf("The PL design files were written in Verilog. Synthesis and Implementation were done using Xilinx Vivado.\n");
	xil_printf("The PS program was written in C, and compiled using Xilinx SDK.\n\r");

	xil_printf("The MicroZed development board can be used as both a stand-alone board, \n");
	xil_printf("or combined with a carrier card as an embeddable system-on-module.\n");
	xil_printf("This implementation was designed to be fully operational even when using the stand-alone mode.\n");
	xil_printf("Plugging the board into the carrier card will activate more indicator LEDs.\n\r");

	xil_printf("This project was created as a final year project, with the guidance of Mr. Uri Stroh.\n");
	xil_printf("We want to thank Mr. Stroh for his guidance and help, \n");
	xil_printf("the Lev Academic Center (JCT) staff for supplying equipment and technical support, \n");
	xil_printf("and the Xilinx and Avnet companies for their fine products, useful documentation and helpful websites.\n\r");
}


/********************************************************************************************************
  18. performance_measurement: infinite loop of simple encryption for easy testing by scope or logic analyzer.
  Data is hard-coded, minimum code lines for minimum real time.
*********************************************************************************************************/
void performance_measurement()
{
	// variables which are relevant for both HW SW only
	u8  text1 [1] = "a";
	u32 key1 = 0;
	u32 key2 = 0;
	u32 key3 = 0;
	u32 key4 = 0;
	u8  result [1] = {0};

	// control
	bool HW_measurement;
	bool op_mode;
	bool only_data ;
	bool enc_dec ; // 1: encryption  0: decryption

	// for user selection flow
	u8 answer;
	bool valid_answer;

	valid_answer = 0;
	do {
		xil_printf("for SW measurement please press '0'.  for HW measurement please press '1'. \n\r");
		scanf(" %c", &answer);
		if (answer == '0')
		{
			valid_answer = 1;
			HW_measurement = 0;
			xil_printf("SW \n");
		}
		else if (answer == '1')
		{
			valid_answer = 1;
			HW_measurement = 1;
			xil_printf("HW \n");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

	valid_answer = 0;
	do {
		xil_printf("For ECB mode, please press '0'.  For CBC mode, please press '1'. \n\r");
		scanf(" %c", &answer);
		if (answer == '0')
		{
			valid_answer = 1;
			op_mode = 0;
			xil_printf("ECB mode \n");
		}
		else if (answer == '1')
		{
			valid_answer = 1;
			op_mode = 1;
			xil_printf("CBC mode \n");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

	valid_answer = 0;
	do {
		xil_printf("to decrypt, please press '0'.  to encrypt, please press '1'. \n\r");
		scanf(" %c", &answer);
		if (answer == '0')
		{
			valid_answer = 1;
			enc_dec = 0;
			xil_printf("decryption \n");
		}
		else if (answer == '1')
		{
			valid_answer = 1;
			enc_dec = 1;
			xil_printf("encryption \n");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);

	valid_answer = 0;
	do {
		xil_printf("to generate key, please press '0'.  For data only, please press '1'. \n\r");
		scanf(" %c", &answer);
		if (answer == '0')
		{
			valid_answer = 1;
			only_data = 0;
			xil_printf("generate key \n");
		}
		else if (answer == '1')
		{
			valid_answer = 1;
			only_data = 1;
			xil_printf("only data \n");
		}
		else
			xil_printf("Not a valid input. \n\r");
	} while (!valid_answer);


	if (HW_measurement==1) //HW
	{
		// variables which are relevant for HW only
		u8  text2 [1] = "b";
		u32 IV1  = 2;
		u32 IV2  = 3;
		bool first_block = 1;
		bool new_IV = 1;

		// first encryption anyway needs for keys preparation
		Zynq_crypt(text1, key1,key2,key3,key4,IV1,IV2,0,enc_dec,op_mode,first_block,new_IV, result); // 0: generate keys
		first_block = 0;
		new_IV = 0;

		xil_printf("Please connect PMOD 'JA p1' to scope or logic analyzer. \n\r");
		xil_printf("You are supposed to see a pulse when PL is busy every loop iteration. \n\r");
		xil_printf("Measure it to know time execution. \n\r");

		while(true)
		{
			Zynq_crypt(text1, key1,key2,key3,key4,IV1,IV2,only_data,enc_dec,op_mode,first_block,new_IV, result);
			Zynq_crypt(text2, key1,key2,key3,key4,IV1,IV2,only_data,enc_dec,op_mode,first_block,new_IV, result);
		}
	}
	else // SW
	{
		// variables which are relevant for SW only
		bool pmod_state = 0;  //PMOD_D0
		struct NESSIEstruct subkeys;
		u8 key[16];
		u8 CBC_xor [1] = "c";

		key[0]  = (u8)(key1 >> 24);
		key[1]  = (u8)(key1 >> 16);
		key[2]  = (u8)(key1 >>  8);
		key[3]  = (u8)(key1      );
		key[4]  = (u8)(key2 >> 24);
		key[5]  = (u8)(key2 >> 16);
		key[6]  = (u8)(key2 >>  8);
		key[7]  = (u8)(key2      );
		key[8]  = (u8)(key3 >> 24);
		key[9]  = (u8)(key3 >> 16);
		key[10] = (u8)(key3 >>  8);
		key[11] = (u8)(key3      );
		key[12] = (u8)(key4 >> 24);
		key[13] = (u8)(key4 >> 16);
		key[14] = (u8)(key4 >>  8);
		key[15] = (u8)(key4      );
		NESSIEkeysetup(key, &subkeys);  // calculate the round keys

		xil_printf("Please connect PMOD 'D0' to scope or logic analyzer. \n\r");
		xil_printf("You are supposed to see sign changing every loop iteration. \n\r");
		xil_printf("Measure it to know time execution. \n\r");

		if (enc_dec == 1) // encryption
		{
			if (only_data == 1)
			{
				if (op_mode==1) //CBC
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEencrypt_CBC(&subkeys, text1, CBC_xor, result);
					}
				}
				else // ECB
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEencrypt(&subkeys, text1, result);
					}
				}
			}
			else  // generate keys
			{
				if (op_mode==1) //CBC
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEkeysetup(key, &subkeys);  // calculate the round keys
						NESSIEencrypt_CBC(&subkeys, text1, CBC_xor, result);
					}
				}
				else // ECB
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEkeysetup(key, &subkeys);  // calculate the round keys
						NESSIEencrypt(&subkeys, text1, result);
					}
				}
			}
		}
		else // decryption
		{
			if (only_data == 1)
			{
				if (op_mode==1) //CBC
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEdecrypt_CBC(&subkeys, text1, CBC_xor, result);
					}
				}
				else // ECB
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEdecrypt(&subkeys, text1, result);
					}
				}
			}
			else  // generate keys
			{
				if (op_mode==1) //CBC
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEkeysetup(key, &subkeys);  // calculate the round keys
						NESSIEdecrypt_CBC(&subkeys, text1, CBC_xor, result);
					}
				}
				else // ECB
				{
					while(true)
					{
						pmod_state = !pmod_state;
						XGpioPs_WritePin(&my_Gpio, 13, pmod_state);
						NESSIEkeysetup(key, &subkeys);  // calculate the round keys
						NESSIEdecrypt(&subkeys, text1, result);
					}
				}
			}
		}
	}
}

#endif