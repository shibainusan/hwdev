include <BOSL2/std.scad>
include <BOSL2/screws.scad>

side_x_size = 70+2+2;
side_y_size = 90;
side_z_size = 2;

tap_hole_depth = 10;

difference(){
	cube(size = [side_x_size, side_y_size, side_z_size], center = false);

//1F	
	translate([12 , 4, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , 4, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//2F
	translate([12 , 4 + 28, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , 4 + 28, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//3F
	translate([12 , 4 + 28*2, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , 4 + 28*2, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//top
	translate([12 , side_y_size - 4, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , side_y_size - 4, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([25 , side_y_size - 16, 0]) {
		cube(size = [25, 8, tap_hole_depth], center = false);
	}
}
