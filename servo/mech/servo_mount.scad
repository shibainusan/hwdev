
base_x_size = 30;
base_y_size = 35.7;
base_z_size = 3;

tap_hole_depth = 10;
tap_hole_r = 1.8/2; //M2.0 - 0.2

difference(){
	cube(size = [base_x_size, base_y_size, base_z_size], center = false);
	
	//切り欠き
	translate([9.1,4.2,0]) {
		cube(size = [11.8, 22.6, 8], center = false);
	}
	
	//servo固定ねじ穴
	translate( [15 ,2.1, base_z_size] ) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate( [15, 31.2 - 2.1, base_z_size] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}


	//Lower固定ねじ穴
	translate( [4.8 , base_y_size - 4.8, base_z_size] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate( [base_x_size - 3.5, 5.7 + 3.5, base_z_size] ) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}

}
