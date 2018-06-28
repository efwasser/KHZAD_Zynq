/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the KHAZAD algorithm linear diffusion layer "theta", using 8 instantiations of "row_mult".
The 64-bit data_in (=state) is separated into eight 8-bit parts, and each one is multiplied by a 32-bit vector, 
which represents a row of the KHAZAD matrix H (zeros not included), to yield a 64-bit result.
The final output data_out is the result of XOR between all the 8 results of row_mult, similar to the method described in: 
P. Barreto and V. Rijmen, The Khazad Legacy-Level Block Cipher, section 7.1
available at: 
https://www.cosic.esat.kuleuven.be/nessie/tweaks.html
*********************************************************************************************************
*********************************************************************************************************/
module theta  // 64-bit to 64-bit transformation
(
  input  [63:0] data_in,
  output [63:0] data_out
);

wire [63:0] T0, T1, T2, T3, T4, T5, T6, T7;

row_mult  R0  (data_in[63:56], 32'h134568b7, T0);
row_mult  R1  (data_in[55:48], 32'h3154867b, T1);
row_mult  R2  (data_in[47:40], 32'h4513b768, T2);
row_mult  R3  (data_in[39:32], 32'h54317b86, T3);
row_mult  R4  (data_in[31:24], 32'h68b71345, T4);
row_mult  R5  (data_in[23:16], 32'h867b3154, T5);
row_mult  R6  (data_in[15: 8], 32'hb7684513, T6);
row_mult  R7  (data_in[ 7: 0], 32'h7b865431, T7);

assign data_out = T0 ^ T1 ^ T2 ^ T3 ^ T4 ^ T5 ^ T6 ^ T7;

endmodule