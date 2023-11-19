include <BOSL2/std.scad>
include <BOSL2/screws.scad>

side_x_size = 70+2+2;
side_y_size = 100;
side_z_size = 2;

tap_hole_depth = 10;
tap_hole_r = 2.8/2; //M3.0 - 0.2

h1F = 3;
h2F = h1F + 30;
h3F = h2F + 35;
hTop = h3F + 32;

fan_mount_xy = 6;
fan_mount_z = 4;

difference(){
	union(){
		cube(size = [side_x_size, side_y_size, side_z_size], center = false);
		//60mm FAN mount
		translate([12 , h1F + 6, 0]) {
			cube(size = [fan_mount_xy, fan_mount_xy, fan_mount_z], center = true);
		}
		translate([side_x_size - 12 , h1F + 6, 0]) {
			cube(size = [fan_mount_xy, fan_mount_xy, fan_mount_z], center = true);
		}
		translate([12 , h1F + 6+ 50, 0]) {
			cube(size = [fan_mount_xy, fan_mount_xy, fan_mount_z], center = true);
		}
		translate([side_x_size - 12 , h1F + 6 + 50, 0]) {
			cube(size = [fan_mount_xy, fan_mount_xy, fan_mount_z], center = true);
		}
	}
//1F	
	translate([12 , h1F, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , h1F, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//2F
	translate([12 , h2F, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , h2F, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//3F
	translate([12 , h3F, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , h3F, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
//top
	translate([12 , side_y_size - 3, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([side_x_size - 12 , side_y_size - 3, side_z_size]) {
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([25 , side_y_size - 16, 0]) {
		cube(size = [25, 8, tap_hole_depth], center = false);
	}
//60mm FAN	
	translate([16 ,6, 0]) {
		cube(size = [42, 60, tap_hole_depth], center = false);
	}
	translate([12 , h1F + 6, side_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([side_x_size - 12 , h1F + 6, side_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([12 , h1F + 6+ 50, side_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
	translate([side_x_size - 12 , h1F + 6 + 50, side_z_size]) {
		cylinder( h = tap_hole_depth, r = tap_hole_r, center = true , $fn=16 );
	}
}
