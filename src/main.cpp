/*  
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
// CONTRIBUTORS AND COPYRIGHT HOLDERS (c) 2013:
// Bob Mottram (bob@robotics.uk.to)
// Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)

#include <iostream>
#include <botan/botan.h>
#include "config.h"
#include "exceptions.h"
#include "unittests.h"

int main(int argc, char* argv[])
{    
    try
    {
        std::cout << LIBRARY_NAME << " " << LIBRARY_VERSION << std::endl;

        Botan::LibraryInitializer init;

        run_unit_tests();               
    }
    catch(bm::BaseException& bmex)
    {
        std::cerr << bmex.file() << " [" << bmex.line() << "]: " << bmex.function() << ": " << bmex.what() << std::endl;
    }
    catch(std::exception& stdex)
    {
        std::cerr << stdex.what() << std::endl;
    }
}
