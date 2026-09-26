#include "parser.h"
#include "run.h"

#include <exception>
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        const auto args = cryptocore::cli::parse(argc, argv);
        return cryptocore::cli::run(args);
    } catch (const std::exception& e) {
        std::cerr << "cryptocore: " << e.what() << "\n";
        return 1;
    }
}