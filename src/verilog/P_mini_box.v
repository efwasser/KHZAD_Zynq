/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the KHAZAD algorithm (Khazad-tweak version) mini-substitution-box "P mini box", 
using logic functions (not memory), as described in: 
P. Barreto and V. Rijmen, The Khazad Legacy-Level Block Cipher, appendix B
available at: 
https://www.cosic.esat.kuleuven.be/nessie/tweaks.html
*********************************************************************************************************
*********************************************************************************************************/
module P_mini_box  // 4-bit to 4-bit substitution box
(
  input  [3:0] data_in,
  output [3:0] data_out
);

wire t0, t1, t1_2, t1_3, t1_4, t2, t2_2, t2_3, t2_4, t3, t3_2, t4, t4_2, t4_3;

assign t0 = data_in[0] ^ data_in[1];
assign t1 = data_in[0] ^ data_in[3];
assign t2 = data_in[2] & t1;
assign t3 = data_in[3] & t1;
assign t4 = t0 | t3;
assign data_out[3] = t2 ^ t4;
assign t1_2 = ~t1;
assign t2_2 = data_in[1] & data_in[2];
assign t4_2 = data_in[3] | data_out[3];
assign t1_3 = t1_2 ^ t2_2;
assign data_out[0] = t4_2 ^ t1_3;
assign t4_3 = data_in[2] & t1_3;
assign t2_3 = t2_2 ^ data_in[3];
assign t2_4 = t2_3 | t4_3;
assign data_out[2] = t0 ^ t2_4;
assign t3_2 = t3 ^ t4_3;
assign t1_4 = t1_3 | data_out[3];
assign data_out[1] = t3_2 ^ t1_4;

endmodule