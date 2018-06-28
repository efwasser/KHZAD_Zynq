/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements polynomial multiplication of 8-bit data_in with a 32-bit vector represents a row of the KHAZAD matrix H, 
using 8 instantiations of "poly_mult".
The 32-bit row_coefficients vector is separated into eight 4-bit parts, each part represents one coefficient of the matrix.
The result of each poly_mult instantiation is 8-bit wide, 
and the final result of multiplication by the entire row is given by the 64-bit data_out output vector.
*********************************************************************************************************
*********************************************************************************************************/
module row_mult  // 8-bit to 64-bit transformation
(
  input   [7:0]  data_in,
  input   [31:0] row_coefficients,
  output  [63:0] data_out
);

poly_mult  M0  (data_in, row_coefficients[31:28], data_out[63:56]);
poly_mult  M1  (data_in, row_coefficients[27:24], data_out[55:48]);
poly_mult  M2  (data_in, row_coefficients[23:20], data_out[47:40]);
poly_mult  M3  (data_in, row_coefficients[19:16], data_out[39:32]);
poly_mult  M4  (data_in, row_coefficients[15:12], data_out[31:24]);
poly_mult  M5  (data_in, row_coefficients[11: 8], data_out[23:16]);
poly_mult  M6  (data_in, row_coefficients[7 : 4], data_out[15 :8]);
poly_mult  M7  (data_in, row_coefficients[3 : 0], data_out[7 : 0]);

endmodule