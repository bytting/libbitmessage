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
#include <sstream>
#include <iostream>
#include <exception>
#include <botan/botan.h>

#include "anyoption.h"
#include "unittests.h"
#include "config.h"

int main(int argc, char* argv[])
{
    AnyOption opt;

    // Usage
    opt.addUsage( LIBRARY_NAME );
    opt.addUsage( "Run unit tests: " );
    opt.addUsage( "  libbitmessage -p 8444" );
    opt.addUsage( " " );
    opt.addUsage( "Usage: " );
    opt.addUsage( "" );
    opt.addUsage( "  -p --port                 Port to listen on");
    opt.addUsage( "  -V --version              Show version number");
    opt.addUsage( "     --help                 Show help");
    opt.addUsage( "" );

    opt.setOption(  "port", 'p' );
    opt.setFlag(  "version", 'V' );
    opt.setFlag(  "help" );

    opt.processCommandArgs(argc, argv);

    if ((!opt.hasOptions()) || (opt.getFlag( "help" )))
    {
		// print usage if no options
        opt.printUsage();
        return 0;
	}

    if ((opt.getFlag("version")) || (opt.getFlag('V')))
    {
        std::cout << "Version " << LIBRARY_VERSION << std::endl;
        return 0;
	}

	int port = 8444;
    if ((opt.getValue("port") != NULL) || (opt.getValue('p')))
    {
        std::stringstream ss;
        ss << opt.getValue("port");
        ss >> port;
	}	

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
