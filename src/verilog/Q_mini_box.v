/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the KHAZAD algorithm (Khazad-tweak version) mini-substitution-box "Q mini box", 
using logic functions (not memory), as described in: 
P. Barreto and V. Rijmen, The Khazad Legacy-Level Block Cipher, appendix B
available at: 
https://www.cosic.esat.kuleuven.be/nessie/tweaks.html
*********************************************************************************************************
*********************************************************************************************************/
module Q_mini_box  // 4-bit to 4-bit substitution box
(
  input  [3:0] data_in,
  output [3:0] data_out
);

wire t0, t0_2, t0_3, t0_4, t1, t1_2, t1_3, t1_4, t1_5, t2, t3, t3_2, t3_3, t4;

assign t0 = ~data_in[0];
assign t1 = data_in[1] ^ data_in[2];
assign t2 = data_in[2] & t0;
assign t3 = data_in[3] ^ t2;
assign t4 = t1 & t3;
assign data_out[0] = t0 ^ t4;
assign t0_2 = data_in[0] ^ data_in[1];
assign t1_2 = t1 ^ t2;
assign t0_3 = t0_2 ^ t3;
assign t1_3 = t1_2 | t0_3;
assign data_out[2] = data_in[2] ^ t1_3;
assign t1_4 = t1_3 & data_in[0];
assign t3_2 = data_in[3] & t0_3;
assign t3_3 = t3_2 ^ t2;
assign data_out[1] = t1_4 ^ t3_3;
assign t1_5 = data_in[2] | data_out[0];
assign t0_4 = t0_3 ^ t3_3;
assign data_out[3] = t1_5 ^ t0_4;

endmodule