/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module manages control signals between the PS program and the PL design, and some indicator LEDs output.
Input ctrl_from_PS[3:0] is received from the PS via AXI:
	  ctrl_from_PS[3] - RST 								1: reset command. 0: no reset command.
	  ctrl_from_PS[2] - only_data 							1: new data, same key. 0: new data and new key.
	  ctrl_from_PS[1] - enc_dec_SEL: the desired operation	1: encryption. 0: decryption.
	  ctrl_from_PS[0] - bistable input start/ready flag. To start an operation this bit must not be equal to the ctrl_to_PS flag (start_condition=1).
	  When bits are equal, start_condition=0, and the PS will be notified that operation has ended.
Input finish: a pulse from KHAZAD when last_round has ended.
Output ctrl_to_PS: bistable output start/ready flag sent to the PS via AXI to notify PS that operation has ended.
*********************************************************************************************************
*********************************************************************************************************
Version 1.0: ECB implementation
*********************************************************************************************************
*********************************************************************************************************/
module controller
(
input   		   CLK			   , 
input   	[3:0]  ctrl_from_PS    ,  
input 		  	   finish 		   ,
output   		   RST			   ,
output   		   only_data	   ,
output   		   enc_dec_SEL	   ,
output  	 	   start		   ,
output  reg	  	   ctrl_to_PS	   ,
output			   RST_LED		   ,
output			   encryption_LED  ,
output			   decryption_LED  ,
output  		   PL_ready_LED
);

assign RST 				= ctrl_from_PS[3];
assign only_data 	    = ctrl_from_PS[2];
assign enc_dec_SEL  	= ctrl_from_PS[1];

wire start_condition;
reg  start_EN;

assign start_condition = ctrl_from_PS[0] ^ ctrl_to_PS;
assign start = start_condition & start_EN; // start_EN makes start a one-cycle pulse

always @(posedge CLK)
begin
	if (RST)
		ctrl_to_PS <= 0;
	else if (finish) 				   // a pulse from KHAZAD when last_round has ended
		ctrl_to_PS <= ctrl_from_PS[0]; // when bits are equal, start_condition=0, and PS notified that operation has ended
end

always @(posedge CLK)
begin
	if (RST)
		start_EN <= 1;
	else
		begin
			if (!start_condition)
				start_EN <= 1;
			else if (start_EN)
				start_EN <= 0;
		end
end

// Indicator LEDs output:
assign RST_LED = RST;
assign encryption_LED = enc_dec_SEL;
assign decryption_LED = !enc_dec_SEL;
assign PL_ready_LED = (!RST) && (!start_condition); // =nor. LED ON when KHAZAD waiting, OFF when busy

endmodule