/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the pre-KHAZAD calculation needs to be done for CBC-mode encryption: XOR with the 
Initialization Vector (IV) for first_block = 1, or with the last KHAZAD cipher output (Cminus1) for first_block = 0.
For CBC-mode decryption and for ECB-mode, this module does nothing.
*********************************************************************************************************
*********************************************************************************************************/
module op_mode_enc
(
  input				op_mode		,   // 0: ECB  1:CBC
  input  	 [63:0] d_in		,
  input  	 [63:0] Cminus1		,
  input 	 [63:0] IV			,
  input	 	 	    enc_dec_SEL	,   // 0: dec  1: enc
  input  			first_block	,
  output reg [63:0] d_out
);

always @(*)
begin
	if ((enc_dec_SEL == 0)||(op_mode == 0))  // for decryption and for ECB-mode do nothing
		d_out <= d_in;
	else									 // for CBC-mode encryption
		begin
			if (first_block == 1)
				d_out <= d_in ^ IV;
			else
				d_out <= d_in ^ Cminus1;
		end
end

endmodule