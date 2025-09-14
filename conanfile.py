from conan import ConanFile
from conan.tools.cmake import cmake_layout


class TestRecipe(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "PkgConfigDeps", "CMakeDeps", "CMakeToolchain"

    def requirements(self):

        self.requires("openssl/3.5.2")
        self.requires("gtest/1.17.0")
        
    def build_requirements(self):
        pass

    def layout(self):
        cmake_layout(self)

    def configure(self):
        self.settings.compiler.cppstd = "23"
