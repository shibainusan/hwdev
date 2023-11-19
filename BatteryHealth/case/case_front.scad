include <BOSL2/std.scad>
include <BOSL2/screws.scad>

front_x_size = 90;
front_y_size = 90;
front_z_size = 2;

tap_hole_depth = 10;

sma_holes_x = 36;
sma_holes_y = 16;

led_hole_r = 2.5;
led_hole_y = 27;

difference(){
	cube(size = [front_x_size, front_y_size, front_z_size], center = false);

//1F	
	translate([15 , 4, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([front_x_size - 15 , 4, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([0 , 8, 0]) {
		cube( [ sma_holes_x, sma_holes_y, tap_hole_depth], center = false );
	}
	translate([front_x_size - sma_holes_x, 8, 0]) {
		cube( [ sma_holes_x, sma_holes_y, tap_hole_depth], center = false );
	}
	translate([7 , led_hole_y, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}
	translate([29 , led_hole_y, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 7 , led_hole_y, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 29 , led_hole_y, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}

//2F
	translate([15 , 4 + 28, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([front_x_size - 15 , 4 + 28, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([0 , 8 + 28, 0]) {
		cube( [ sma_holes_x, sma_holes_y, tap_hole_depth], center = false );
	}
	translate([front_x_size - sma_holes_x, 8 + 28, 0]) {
		cube( [ sma_holes_x, sma_holes_y, tap_hole_depth], center = false );
	}
	translate([7 , led_hole_y + 28, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}
	translate([29 , led_hole_y + 28, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 7 , led_hole_y + 28, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}
	translate([front_x_size - 29 , led_hole_y + 28, front_z_size]) {
		cylinder( h = tap_hole_depth, r = led_hole_r, center = true , $fn=16 );
	}

//3F
	translate([15 , 4 + 28*2, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([front_x_size - 15 , 4 + 28*2, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//top
	translate([15 , front_y_size - 4, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([front_x_size - 15 , front_y_size - 4, front_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
}


