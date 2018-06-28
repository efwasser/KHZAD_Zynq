/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module is merely an intermediate between the PS and the PL design.
It concatenates the four 32-bit key_in parts input into one 128-bit key for the PL,
the two 32-bit d_in parts input into one 64-bit d_in for the PL,
and splits the 64-bit d_out output into two 32-bit d_out for the PS.
*********************************************************************************************************
*********************************************************************************************************
Version 1.0: ECB implementation
*********************************************************************************************************
*********************************************************************************************************/
module wiring
(
  input  [31:0] k_in_1	,
  input  [31:0] k_in_2	,
  input  [31:0] k_in_3	,
  input  [31:0] k_in_4	,
  input  [31:0] d_in_1	,
  input  [31:0] d_in_2	,
  input  [63:0] d_out 	,
  output [127:0] k_in	,
  output [63:0] d_in 	,
  output [31:0] d_out_1 ,
  output [31:0] d_out_2 
);

assign k_in = {k_in_1, k_in_2, k_in_3, k_in_4};
assign d_in = {d_in_1, d_in_2};
assign d_out_1 = d_out[63:32];
assign d_out_2 = d_out[31:0];

endmodule