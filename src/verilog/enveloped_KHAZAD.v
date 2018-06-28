/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
Module KHAZAD by itself can only give results for ECB mode. This module envelops module KHAZAD together with the 
modules and wiring necessary to implement CBC mode: op_mode_enc, CBC_dec_memory, op_mode_dec.
The initial d_in is going into modules op_mode_enc and CBC_dec_memory, coming out of op_mode_enc as d_in_KHAZAD, 
then going into KHAZAD.
KHAZAD output is coming out as d_out_KHAZAD, then going into op_mode_enc (for possible future XOR) 
and into op_mode_dec. The final output is going out of op_mode_dec as d_out.
Cminus1 is the output of module CBC_dec_memory, and it is used in module op_mode_dec.
*********************************************************************************************************
*********************************************************************************************************/
module enveloped_KHAZAD
(
input   		CLK				,
input  			RST				,
input  [127:0]  k_in			,
input  [63:0]   d_in			,
input  [63:0]   IV				,
input 			only_data		,
input 			enc_dec_SEL		,
input 			op_mode			,
input 			first_block		,
input  	        start			,
output [63:0]   d_out 			,
output 		    last_round 			
);

wire [63:0] d_in_KHAZAD, d_out_KHAZAD, Cminus1;

op_mode_enc		op_mode_1  (op_mode, d_in, d_out_KHAZAD, IV, enc_dec_SEL, first_block, d_in_KHAZAD);
KHAZAD  		KHZD 	   (d_in_KHAZAD, k_in, CLK, RST, enc_dec_SEL, start, only_data, d_out_KHAZAD, last_round);
CBC_dec_memory  CBC_mem    (CLK, RST, start, d_in, Cminus1);
op_mode_dec     op_mode_2  (op_mode, d_out_KHAZAD, Cminus1, IV, enc_dec_SEL, first_block, d_out);

endmodule