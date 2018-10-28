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
Version 3.0: ECB & CBC implementation, Hardware & Software
*********************************************************************************************************
*********************************************************************************************************/

#include "KHAZAD_Zynq.h"


int main()
{
  init_platform(); // register initialization and UART setup
  xil_printf("*************************************************************** \n");
  xil_printf("*************************************************************** \n\r");
  xil_printf("KHAZAD block cipher hardware implementation using the Zynq-7000 device and the MicroZed development board \n\r");
  xil_printf("Yossef Shitzer & Efraim Wasserman \n\r");
  xil_printf("Jerusalem College of Technology - Lev Academic Center (JCT) \n\r");
  xil_printf("Department of electrical and electronic engineering \n\r");
  xil_printf("2018 \n\r");
  xil_printf("*************************************************************** \n");
  xil_printf("*************************************************************** \n\r");

  // Peripherals and interrupt configuration:
  board_configuration();

  xil_printf("AXI_GPIO0 address = 0x%x \n\r", ADDR0);
  xil_printf("AXI_GPIO1 address = 0x%x \n\r", ADDR1);
  xil_printf("AXI_GPIO2 address = 0x%x \n\r", ADDR2);
  xil_printf("AXI_GPIO3 address = 0x%x \n\r", ADDR3);
  xil_printf("AXI_GPIO4 address = 0x%x \n\r", ADDR4);
  xil_printf("AXI_GPIO address offset = 0x%08x \n\r", ADDR_offset);

  // PL design initialization:
  /* ctrl is received in the PL as signal ctrl_from_PS[5:0]:
	 bit 5 - RST
	 bit 4 - only_data. 											1: new data, same key. 0: new data and new key.
	 bit 3 - enc_dec: the desired operation.					    1: encryption. 0: decryption.
	 bit 2 - op_mode: the desired cryptographic mode of operation.  1: CBC. 0: ECB.
	 bit 1 - first_block: flag for the CBC mode. 					1: first data block. 0: not first data block.
	 bit 0 - bistable start/ready semaphore flag. To run an operation this bit must not be equal to a matching flag in the PL. */
  XGpioPs_WritePin(&my_Gpio, 47, 0); // turn off the PS-ready indicator LED
  ctrl = 0x0020; // reset=1
  Xil_Out16(ADDR0,ctrl); // send from PS to FPGA via AXI interface
  usleep(50000);
  ctrl = 0x0000; // reset=0
  Xil_Out16(ADDR0,ctrl);
  XGpioPs_WritePin(&my_Gpio, 47, 1); // turn on the LED

  xil_printf("*************************************************************** \n\r");
  xil_printf("Welcome to the KHAZAD block cipher hardware implementation! \n\r");
  bool go = 1;
  u8 option;
  while (go) {
	  xil_printf("*************************************************************** \n\n\r");
	  xil_printf("Please choose an option: \n\n\r");
	  xil_printf("--1-- \t Hardware encryption/decryption \n\r");
	  xil_printf("--2-- \t Software encryption/decryption \n\r");
	  xil_printf("--3-- \t Combined ECB correctness demonstration \n\r");
	  xil_printf("--4-- \t Test vectors \n\r");
	  xil_printf("--5-- \t Random vectors test \n\r");
	  xil_printf("--6-- \t CBC-MAC generator \n\r");
	  xil_printf("--7-- \t CSPRNG: Cryptographically Secure Pseudo-Random Number Generator \n\r");
	  xil_printf("--8-- \t About \n\r");
	  // xil_printf("--9-- \t Performance measurement \n\r"); - testing mode only
	  xil_printf("--0-- \t Exit \n\r");
	  xil_printf("To reset the FPGA design, you may press the MicroZed user button at any time. \n");
	  xil_printf("(Resetting the design while mid-operation may lead to wrong results.) \n\r");
	  scanf(" %c", &option);

	  switch(option) {
	  case '1':
		  HW_application();
		  break;
	  case '2':
		  SW_application();
		  break;
	  case '3':
		  demonstration();
		  break;
	  case '4':
		  test_vectors();
		  break;
	  case '5':
		  random_vectors_test();
		  break;
	  case '6':
		  CBC_MAC();
		  break;
	  case '7':
		  PRNG_application();
		  break;
	  case '8':
		  about();
		  break;
	 /* case '9':
		  performance_measurement();
		  break; */
	  case '0':
		  go = 0;
		  xil_printf("Thanks for using this design. Goodbye! \n\r");
		  break;
	  default:
		  xil_printf("Not a valid input. \n\r");
	  }
  }

  cleanup_platform(); // cleanup, disable cache
  return 0;
}