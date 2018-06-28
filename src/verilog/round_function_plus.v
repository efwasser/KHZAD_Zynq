/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the KHAZAD round function "rho", using instantiations of previous modules.
The complete round function, used in most rounds of the cipher and in the key schedule, is composed of the "gamma" function, 
then "theta", then XOR with round_key (which is an actual round key for the cipher, or some round constant for the key schedule).
In the last round of the cipher, only gamma and XOR are used.
Similarly, to calculate the "inverse" key rounds, required for decryption, only the theta function is used, by turning on the "only_theta_req" signal.
So the module is used not only for the complete round function but also for the last round function and for theta only.
The word "plus" in the module's name refers to that fact.
The above operations are all described in: 
P. Barreto and V. Rijmen, The Khazad Legacy-Level Block Cipher, section 3
available at: 
https://www.cosic.esat.kuleuven.be/nessie/tweaks.html
*********************************************************************************************************
*********************************************************************************************************/
module round_function_plus
(
  input  [63:0] data_in,
  input  [63:0] round_key,
  input  only_theta_req,
  output [63:0] theta_out,
  output [63:0] last_round_out,
  output [63:0] rho_out
);

wire [63:0] gamma_out, theta_in;

gamma  G  (data_in, gamma_out);

assign theta_in = (only_theta_req == 1) ? data_in : gamma_out;

theta  T  (theta_in, theta_out);  				// theta_out is the output for the inverse key rounds

assign last_round_out = gamma_out ^ round_key;  // last_round_out is the output for the cipher's last round

assign rho_out = theta_out ^ round_key; 		// rho_out is the output for the complete round function

endmodule