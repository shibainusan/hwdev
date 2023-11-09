
back_x_size = 90;
back_y_size = 80;
back_z_size = 2;

tap_hole_depth = 10;
tap_hole_r = 2.8/2; //M3.0 - 0.2

difference(){
	cube(size = [back_x_size, back_y_size, back_z_size], center = false);

//1F	
	translate([15 , 4, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([back_x_size - 15 , 4, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
//2F
	translate([15 , 4 + 28, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([back_x_size - 15 , 4 + 28, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
//3F
	translate([15 , 4 + 28*2, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([back_x_size - 15 , 4 + 28*2, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
//top
	translate([15 , 4 + 28*2 + 16, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([back_x_size - 15 , 4 + 28*2 + 16, back_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}

}
