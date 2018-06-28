/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the KHAZAD algorithm (Khazad-tweak version) substitution-box "S box", 
using instantiations of "P" and "Q" mini-boxes, as described in: 
P. Barreto and V. Rijmen, The Khazad Legacy-Level Block Cipher, section 6.2
available at: 
https://www.cosic.esat.kuleuven.be/nessie/tweaks.html
*********************************************************************************************************
*********************************************************************************************************/
module S_box  // 8-bit to 8-bit substitution box
(
  input  [7:0] data_in,
  output [7:0] data_out
);

wire [3:0] p1, q1, p2, q2, p3, q3;

P_mini_box 	P_mini_box_1  (data_in[7:4], p1);
Q_mini_box  Q_mini_box_1  (data_in[3:0], q1);
P_mini_box 	P_mini_box_2  ({p1[1:0], q1[1:0]}, p2);
Q_mini_box 	Q_mini_box_2  ({p1[3:2], q1[3:2]}, q2);
P_mini_box 	P_mini_box_3  ({q2[3:2], p2[3:2]}, p3);
Q_mini_box 	Q_mini_box_3  ({q2[1:0], p2[1:0]}, q3);

assign data_out = {p3, q3};

endmodule