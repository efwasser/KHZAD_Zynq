/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the KHAZAD algorithm (Khazad-tweak version) nonlinear layer "gamma", using 8 instantiations of the "S" substitution box.
The 64-bit data_in (=state) is separated into eight 8-bit parts, and each one is going into an S-box, as described in: 
P. Barreto and V. Rijmen, The Khazad Legacy-Level Block Cipher, section 3.1
available at: 
https://www.cosic.esat.kuleuven.be/nessie/tweaks.html
*********************************************************************************************************
*********************************************************************************************************/
module gamma  // 64-bit to 64-bit transformation
(
  input  [63:0] data_in,
  output [63:0] data_out
);

S_box 	S0 	(data_in[63:56], data_out[63:56]);
S_box 	S1 	(data_in[55:48], data_out[55:48]);
S_box 	S2 	(data_in[47:40], data_out[47:40]);
S_box 	S3 	(data_in[39:32], data_out[39:32]);
S_box 	S4 	(data_in[31:24], data_out[31:24]);
S_box 	S5 	(data_in[23:16], data_out[23:16]);
S_box 	S6 	(data_in[15: 8], data_out[15: 8]);
S_box 	S7 	(data_in[ 7: 0], data_out[ 7: 0]);

endmodule