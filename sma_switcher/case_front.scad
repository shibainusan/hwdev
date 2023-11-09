front_x_size = 90;
front_y_size = 80;
front_z_size = 2;

tap_hole_depth = 10;
tap_hole_r = 2.8/2; //M3.0 - 0.2

sma_holes_x = 36;
sma_holes_y = 16;

difference(){
	cube(size = [front_x_size, front_y_size, front_z_size], center = false);

//1F	
	translate([15 , 4, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 15 , 4, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([back_x_size - 15 , 4, back_z_size]) {
		cube( [ sma_holes_x, sma_holes_y, tap_hole_depth], center = false );
	}

//2F
	translate([15 , 4 + 28, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 15 , 4 + 28, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
//3F
	translate([15 , 4 + 28*2, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 15 , 4 + 28*2, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
//top
	translate([15 , 4 + 28*2 + 16, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 15 , 4 + 28*2 + 16, front_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
}


