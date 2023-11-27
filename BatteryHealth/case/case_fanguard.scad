include <BOSL2/std.scad>
include <BOSL2/screws.scad>

guard_x_size = 60;
guard_y_size = 60;
guard_z_size = 3;

guard_hole_x = 8;
guard_hole_y = 6;
guard_hole_z = 8;

tap_hole_depth = 10;
//tap_hole_r = 2.8/2; //M3.0 - 0.2

h1F = 3;
h2F = h1F + 30;
h3F = h2F + 35;
hTop = h3F + 32;

difference(){

	union(){
		difference(){
			cube(size = [guard_x_size, guard_y_size, guard_z_size], center = false);
			translate([2 , 2, 2]) {
				cube(size = [guard_x_size - 4, guard_y_size - 4, 1], center = false);
			}
		}
		translate([5 , 5, 2]) {
			cube(size = [10, 10, 2], center = true);
		}
		translate([guard_x_size - 5 , 5, 2]) {
			cube(size = [10, 10, 2], center = true);
		}
		translate([5 , guard_y_size - 5, 2]) {
			cube(size = [10, 10, 2], center = true);
		}
		translate([guard_x_size - 5 , guard_y_size - 5, 2]) {
			cube(size = [10, 10, 2], center = true);
		}
	}

	translate([5 , 5, 0]) rotate(a = [180, 0, 0]){
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}	
	translate([guard_x_size - 5 , 5, 0]) rotate(a = [180, 0, 0]){
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([5 , guard_y_size - 5, 0]) rotate(a = [180, 0, 0]){
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	translate([guard_x_size - 5 , guard_y_size - 5, 0])  rotate(a = [180, 0, 0]){
		screw_hole("M3,10",head="flat",counterbore=0,anchor=TOP);
	}
	
	
	for( x = [14: 10: 50]){
		for( y = [5: 8: 56]){
			translate([x , y, 0]) {
				cube(size = [guard_hole_x, guard_hole_y, guard_hole_z], center = true);
			}
		}
	}
	for( y = [5+8: 8: 48]){
		translate([5 , y, 0]) {
			cube(size = [guard_hole_x-2, guard_hole_y, guard_hole_z], center = true);
		}
	}
	
	for( y = [5+8: 8: 48]){
		translate([54 , y, 0]) {
			cube(size = [guard_hole_x, guard_hole_y, guard_hole_z], center = true);
		}
	}
}
