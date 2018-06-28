/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements modular polynomial multiplication over GF(2^8), 
with the KHAZAD reduction polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 100011101 = 00011101 (upper bit exceeds limits and omitted).
The multiplications are calculated based upon multiplications by 2, 4 and 8.
Each additional multiplication by 2 is a one-place left shift, with conditional XOR if MSB = 1.
This condition is implemented by logical AND with "and_mask", which is replications of the MSB.
*********************************************************************************************************
*********************************************************************************************************/
module poly_mult  // 8-bit to 8-bit transformation
(
  input      [7:0] data_in,
  input      [3:0] multiplier,
  output reg [7:0] data_out
);

wire [7:0] and_mask   = {8{data_in[7]}};  								     // mask for multiplication by 2
wire [7:0] mult2 	  = ({data_in[6:0],1'h0}) ^ ((8'b00011101) & and_mask);  // multiplication by 2
wire [7:0] and_mask_2 = {8{mult2[7]}};  									 // mask for multiplication by 4
wire [7:0] mult4 	  = ({mult2[6:0],1'h0}) ^ ((8'b00011101) & and_mask_2);  // multiplication by 4
wire [7:0] and_mask_3 = {8{mult4[7]}}; 										 // mask for multiplication by 8
wire [7:0] mult8	  = ({mult4[6:0],1'h0}) ^ ((8'b00011101) & and_mask_3);  // multiplication by 8

always @(*)
case (multiplier)  // only the cases possible in KHAZAD
	4'h1: data_out = data_in					;
	4'h3: data_out = mult2 ^ data_in			;  // 3=2+1
	4'h4: data_out = mult4						;
	4'h5: data_out = mult4 ^ data_in			;  // 5=4+1
	4'h6: data_out = mult4 ^ mult2				;  // 6=4+2
	4'h7: data_out = mult4 ^ mult2 ^ data_in	;  // 7=4+2+1
	4'h8: data_out = mult8						;
	4'hb: data_out = mult8 ^ mult2 ^ data_in	;  // b=11=8+2+1
	default: data_out = 8'h0					;
endcase

endmodule