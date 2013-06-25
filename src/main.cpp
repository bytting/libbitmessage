/*
  cppbitmessage: a bitmessage daemon
  Copyright (C) 2013 Bob Mottram
  bob@robotics.uk.to

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.  
*/
/*
 * CONTRIBUTORS:
 * Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)
 *
 */

#include <exception>
#include <iostream>
#include <botan/botan.h>
#include "config.h"
#include "unittests.h"

int main(int argc, char* argv[])
{
    try
    {
        Botan::LibraryInitializer init;
        //bm_run_unit_tests();
    }
    catch(std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
    }
}
