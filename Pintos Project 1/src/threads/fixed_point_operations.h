#ifndef FIXED_POINT_OPERATIONS_H
#define FIXED_POINT_OPERATIONS_H

typedef int fixed;

int fixed_to_int(fixed x);
fixed int_to_fixed(int n);
fixed add_fixed(fixed x, fixed y);
fixed add_fixed_and_int(fixed x, int n);
fixed sub_fixed(fixed x, fixed y);
fixed sub_fixed_and_int(fixed x, int n);
fixed multi_fixed(fixed x, fixed y);
fixed multi_fixed_and_int(fixed x, int n);
fixed div_fixed(fixed x, fixed y);
fixed div_fixed_and_int(fixed x, int n);

int f= 1 << 14;

// converions
fixed int_to_fixed(int n){
  return n*f;
}
int fixed_to_int(fixed x){
  if (x>=0)
    return (x+f/2)/f;
  else
    return (x-f/2)/f;
}

// additions
fixed add_fixed_and_int(fixed x, int n){
  return x + int_to_fixed(n);
}

// sub
fixed sub_fixed_and_int(fixed x, int n){
  return x - int_to_fixed(n);
}

// multi
fixed multi_fixed(fixed x, fixed y){
  return ((int64_t)x)*y/f;
}

// division
fixed div_fixed(fixed x, fixed y){
  return ((int64_t)x)*f/y;
}

#endif
