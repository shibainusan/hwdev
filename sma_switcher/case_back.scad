include <BOSL2/std.scad>
include <BOSL2/screws.scad>

back_x_size = 90;
back_y_size = 90;
back_z_size = 2;

tap_hole_depth = 10;
//tap_hole_r = 2.8/2; //M3.0 - 0.2

difference(){
	cube(size = [back_x_size, back_y_size, back_z_size], center = false);

//1F	
	translate([15 , 4, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([back_x_size - 15 , 4, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//2F
	translate([15 , 4 + 28, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([back_x_size - 15 , 4 + 28, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//3F
	translate([15 , 4 + 28*2, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([back_x_size - 15 , 4 + 28*2, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//top
	translate([15 , back_y_size - 4, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([back_x_size - 15 , back_y_size - 4, back_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}

}
