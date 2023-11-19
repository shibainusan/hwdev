
base_x_size = 90;
base_y_size = 70;
base_z_size = 6;

tap_hole_depth = 10;
tap_hole_r = 2.8/2; //M3.0 - 0.2

difference(){
	cube(size = [base_x_size, base_y_size, base_z_size], center = false);
	
	
	//backパネルねじ穴
	translate( [15 ,tap_hole_depth/2, base_z_size/2] ) rotate(a = [90, 0, 0] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate( [base_x_size - 15, tap_hole_depth/2, base_z_size/2] ) rotate(a = [90, 0, 0] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}

	//サイドパネルねじ穴
	translate( [tap_hole_depth/2, 10, base_z_size/2] ) rotate(a = [0, 90, 00] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate( [ tap_hole_depth/2, base_y_size - 10, base_z_size/2] ) rotate(a = [0, 90, 00] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate( [base_x_size - tap_hole_depth/2, 10, base_z_size/2] ) rotate(a = [0, 90, 00] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate( [base_x_size - tap_hole_depth/2, base_y_size - 10, base_z_size/2] ) rotate(a = [0, 90, 00] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}	

	//frontパネルねじ穴
	translate( [15 , base_y_size - tap_hole_depth/2, base_z_size/2] ) rotate(a = [90, 0, 0] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate( [base_x_size - 15, base_y_size - tap_hole_depth/2, base_z_size/2] ) rotate(a = [90, 0, 0] ){
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}

}
