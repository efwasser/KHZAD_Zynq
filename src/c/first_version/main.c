/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
Main program file
*********************************************************************************************************
*********************************************************************************************************
Version 1.0: ECB implementation
*********************************************************************************************************
*********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h> // for usleep
#include "platform.h"
#include "xgpio.h"
#include "xgpiops.h"
#include "Xscugic.h"
#include "xil_exception.h"
#include "nessie_modified.h"
#include "KHAZAD_Zynq.h"

int main()
{
  init_platform(); // register initialization and UART setup
  printf("*************************************************************** \n");
  printf("*************************************************************** \n\r");
  printf("KHAZAD block cipher hardware implementation using the Zynq-7000 device and the MicroZed development board \n\r");
  printf("Yossef Shitzer & Efraim Wasserman \n\r");
  printf("Jerusalem College of Technology - Lev Academic Center (JCT) \n\r");
  printf("Department of electrical and electronic engineering \n\r");
  printf("2018 \n\r");
  printf("*************************************************************** \n");
  printf("*************************************************************** \n\r");

  // Peripherals and interrupt configuration:
  board_configuration();

  printf("AXI_GPIO0 address = 0x%x \n\r", ADDR0);
  printf("AXI_GPIO1 address = 0x%x \n\r", ADDR1);
  printf("AXI_GPIO2 address = 0x%x \n\r", ADDR2);
  printf("AXI_GPIO3 address = 0x%x \n\r", ADDR3);
  printf("AXI_GPIO address offset = 0x%08x \n\r", ADDR_offset);

  // PL design initialization:
  /* ctrl is received in the PL as signal ctrl_from_PS[3:0]:
	 bit 3 - RST
	 bit 2 - only_data. only_data = 1: new data, same key. only_data = 0: new data and new key.
	 bit 1 - enc_dec: the desired operation. enc_dec = 1: encryption, enc_dec = 0: decryption.
	 bit 0 - bistable start/ready semaphore flag. To run an operation this bit must not be equal to a matching flag in the PL. */
  XGpioPs_WritePin(&my_Gpio, 47, 0); // turn off the PS-ready indicator LED
  ctrl = 0x0008; // reset=1
  Xil_Out16(ADDR0,ctrl); // send from PS to FPGA via AXI interface
  usleep(50000);
  ctrl = 0x0000; // reset=0
  Xil_Out16(ADDR0,ctrl);
  XGpioPs_WritePin(&my_Gpio, 47, 1); // turn on the LED

  printf("*************************************************************** \n\r");
  printf("Welcome to the KHAZAD block cipher hardware implementation! \n\r");
  bool go = 1;
  u8 option;
  while (go) {
	  printf("*************************************************************** \n\n\r");
	  printf("Please choose an option: \n\n\r");
	  printf("--1-- \t Hardware implementation application \n\r");
	  printf("--2-- \t Hardware implementation correctness demonstration \n\r");
	  printf("--3-- \t Test vectors - full version. Warning: this test may take a long time \n\r");
	  printf("--4-- \t Test vectors - short version \n\r");
	  printf("--5-- \t About \n\r");
	  printf("--6-- \t Exit \n\r");
	  printf("To reset the FPGA design, you may press the MicroZed user button at any time. \n");
	  printf("(Resetting the design while mid-operation may lead to wrong results.) \n\r");
	  scanf(" %c", &option);

	  switch(option) {
	  case '1':
		  hardware_implementation();
		  break;
	  case '2':
		  demonstration();
		  break;
	  case '3':
		  test_vectors_full();
		  break;
	  case '4':
		  test_vectors_short();
		  break;
	  case '5':
		  about();
		  break;
	  case '6':
		  go = 0;
		  printf("Thanks for using this design. Goodbye! \n\r");
		  break;
	  default:
		  printf("Not a valid input. \n\r");
	  }
  }

  cleanup_platform(); // cleanup, disable cache
  return 0;
}
