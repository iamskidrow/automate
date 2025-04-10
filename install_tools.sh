#!/bin/bash

# Configuration file parser
parse_config() {
    if [[ ! -f "$1" ]]; then
        echo "Configuration file not found: $1"
        exit 1
    fi

    # Parse JSON config using jq if available, otherwise use Python
    if command -v jq &> /dev/null; then
        echo "Using jq to parse config"
    elif command -v python3 &> /dev/null; then
        echo "Using Python to parse config"
    else
        echo "Error: Neither jq nor python3 is available for parsing JSON config"
        echo "Please install either jq or python3 to continue"
        exit 1
    fi

    CONFIG_FILE="$1"
}

# Detect OS and package manager
detect_system() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
        echo "Detected macOS system, using Homebrew"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        # Detect default package manager on Linux
        if command -v apt-get &> /dev/null; then
            PKG_MANAGER="apt"
            echo "Detected Linux system with apt package manager"
        elif command -v dnf &> /dev/null; then
            PKG_MANAGER="dnf"
            echo "Detected Linux system with dnf package manager"
        elif command -v yum &> /dev/null; then
            PKG_MANAGER="yum"
            echo "Detected Linux system with yum package manager"
        elif command -v pacman &> /dev/null; then
            PKG_MANAGER="pacman"
            echo "Detected Linux system with pacman package manager"
        else
            echo "Warning: Could not identify a supported package manager on this Linux system"
            echo "Will attempt to use Homebrew as fallback"
            PKG_MANAGER="brew"
        fi
    else
        echo "Unsupported OS: $OSTYPE"
        exit 1
    fi
}

# Setup prerequisites based on OS
setup_prerequisites() {
    echo "Setting up prerequisites for $OS..."

    if [[ "$OS" == "macos" ]]; then
        # macOS specific prerequisites
        echo "Checking for Xcode Command Line Tools..."
        if ! xcode-select -p &> /dev/null; then
            echo "Installing Xcode Command Line Tools..."
            xcode-select --install
            # Wait for Xcode CLI tools to be installed
            echo "Please complete the Xcode Command Line Tools installation and press Enter to continue..."
            read -r
        else
            echo "Xcode Command Line Tools already installed."
        fi

        # Check and install Rosetta 2 for Apple Silicon
        if [[ $(uname -m) == 'arm64' ]]; then
            echo "Apple Silicon detected, checking for Rosetta 2..."
            if ! /usr/bin/pgrep -q oahd; then
                echo "Installing Rosetta 2..."
                sudo softwareupdate --install-rosetta --agree-to-license
            else
                echo "Rosetta 2 already installed."
            fi
        fi
    elif [[ "$OS" == "linux" ]]; then
        # Linux specific prerequisites
        echo "Installing required development tools..."
        case $PKG_MANAGER in
            apt)
                sudo apt-get update
                sudo apt-get install -y build-essential curl file git python3 python3-pip jq
                ;;
            dnf)
                sudo dnf check-update
                sudo dnf groupinstall -y "Development Tools"
                sudo dnf install -y curl file git python3 python3-pip jq
                ;;
            yum)
                sudo yum update
                sudo yum groupinstall -y "Development Tools"
                sudo yum install -y curl file git python3 python3-pip jq
                ;;
            pacman)
                sudo pacman -Syu --noconfirm
                sudo pacman -S --noconfirm base-devel curl file git python python-pip jq
                ;;
            brew)
                # Only if we're falling back to Homebrew on Linux
                if ! command -v brew &> /dev/null; then
                    echo "Installing Homebrew as fallback..."
                    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

                    test -d ~/.linuxbrew && eval "$(~/.linuxbrew/bin/brew shellenv)"
                    test -d /home/linuxbrew/.linuxbrew && eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
                    echo "eval \$($(brew --prefix)/bin/brew shellenv)" >> ~/.profile
                    # shellcheck disable=SC1090
                    source ~/.profile
                fi
                ;;
        esac
    fi
}

# Install package manager if needed (primarily for Homebrew on macOS)
install_package_manager() {
    if [[ "$OS" == "macos" && "$PKG_MANAGER" == "brew" ]]; then
        if ! command -v brew &> /dev/null; then
            echo "Installing Homebrew for macOS..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

            # Add brew to path based on architecture
            if [[ $(uname -m) == 'arm64' ]]; then
                # shellcheck disable=SC2016
                echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
                eval "$(/opt/homebrew/bin/brew shellenv)"
            else
                # shellcheck disable=SC2016
                echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.zprofile
                eval "$(/usr/local/bin/brew shellenv)"
            fi
            # shellcheck disable=SC1090
            source ~/.zprofile
        else
            echo "Homebrew already installed."
        fi
    fi
}

# Extract the base name from a package path (for Go packages)
extract_package_name() {
    local package="$1"
    # Extract the name part after the last "/"
    # shellcheck disable=SC2155
    local base_name=$(echo "$package" | sed 's|.*/||' | sed 's|@.*||')
    echo "$base_name"
}

# Install system packages
install_system_packages() {
    echo "Installing system packages..."

    if [ "$PKG_MANAGER" == "brew" ]; then
        # Update Homebrew
        brew update

        # Get system packages from config
        # shellcheck disable=SC2155
        local packages=$(jq -r '.packages[] | select(.type == "system") | .name' "$CONFIG_FILE")

        # Install each package
        for package in $packages; do
            echo "Installing system package: $package"
            brew install "$package" || echo "Failed to install $package"
        done
    else
        # For Linux package managers
        # shellcheck disable=SC2155
        local packages=$(jq -r '.packages[] | select(.type == "system") | .name' "$CONFIG_FILE")

        case $PKG_MANAGER in
            apt)
                # Create a list of packages for apt
                local apt_packages=()
                for package in $packages; do
                    # Check if there's a mapping for this package
                    # shellcheck disable=SC2155
                    local apt_name=$(jq -r --arg pkg "$package" '.package_mappings.apt[$pkg] // $pkg' "$CONFIG_FILE")
                    apt_packages+=("$apt_name")
                done

                if [ ${#apt_packages[@]} -gt 0 ]; then
                    echo "Installing apt packages: ${apt_packages[*]}"
                    sudo apt-get install -y "${apt_packages[@]}" || echo "Some packages failed to install"
                fi
                ;;
            dnf)
                # Create a list of packages for dnf
                local dnf_packages=()
                for package in $packages; do
                    # Check if there's a mapping for this package
                    # shellcheck disable=SC2155
                    local dnf_name=$(jq -r --arg pkg "$package" '.package_mappings.dnf[$pkg] // $pkg' "$CONFIG_FILE")
                    dnf_packages+=("$dnf_name")
                done

                if [ ${#dnf_packages[@]} -gt 0 ]; then
                    echo "Installing dnf packages: ${dnf_packages[*]}"
                    sudo dnf install -y "${dnf_packages[@]}" || echo "Some packages failed to install"
                fi
                ;;
            yum)
                # Create a list of packages for yum
                local yum_packages=()
                for package in $packages; do
                    # Check if there's a mapping for this package
                    # shellcheck disable=SC2155
                    local yum_name=$(jq -r --arg pkg "$package" '.package_mappings.yum[$pkg] // $pkg' "$CONFIG_FILE")
                    yum_packages+=("$yum_name")
                done

                if [ ${#yum_packages[@]} -gt 0 ]; then
                    echo "Installing yum packages: ${yum_packages[*]}"
                    sudo yum install -y "${yum_packages[@]}" || echo "Some packages failed to install"
                fi
                ;;
            pacman)
                # Create a list of packages for pacman
                local pacman_packages=()
                for package in $packages; do
                    # Check if there's a mapping for this package
                    # shellcheck disable=SC2155
                    local pacman_name=$(jq -r --arg pkg "$package" '.package_mappings.pacman[$pkg] // $pkg' "$CONFIG_FILE")
                    pacman_packages+=("$pacman_name")
                done

                if [ ${#pacman_packages[@]} -gt 0 ]; then
                    echo "Installing pacman packages: ${pacman_packages[*]}"
                    sudo pacman -S --noconfirm "${pacman_packages[@]}" || echo "Some packages failed to install"
                fi
                ;;
        esac
    fi
}

# Install Go packages
install_go_packages() {
    echo "Installing Go packages..."

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo "Go is not installed. Installing Go first..."

        if [ "$PKG_MANAGER" == "brew" ]; then
            brew install go
        elif [ "$PKG_MANAGER" == "apt" ]; then
            sudo apt-get install -y golang
        elif [ "$PKG_MANAGER" == "dnf" ] || [ "$PKG_MANAGER" == "yum" ]; then
            sudo $PKG_MANAGER install -y golang
        elif [ "$PKG_MANAGER" == "pacman" ]; then
            sudo pacman -S --noconfirm go
        fi

        # Check if Go installation was successful
        if ! command -v go &> /dev/null; then
            echo "Failed to install Go. Skipping Go packages."
            return
        fi
    fi

    # Create proper user-writable Go directories
    mkdir -p "$HOME/go/bin"

    # Set up GOPATH if not set
    export GOPATH="$HOME/go"
    export GOBIN="$HOME/go/bin"
    export PATH="$PATH:$HOME/go/bin"

    # Get Go packages from config
    # shellcheck disable=SC2155
    local packages=$(jq -r '.packages[] | select(.type == "go") | .name' "$CONFIG_FILE")

    # Install each package
    for package in $packages; do
        # shellcheck disable=SC2155
        local package_name=$(extract_package_name "$package")
        echo "Installing Go package: $package_name (from $package)"

        # Use modular GO111MODULE=on mode for installation
        GO111MODULE=on go install "github.com/$package"

        # Check if installation succeeded
        # shellcheck disable=SC2181
        if [ $? -eq 0 ]; then
            echo "Successfully installed $package_name to $GOPATH/bin"
        else
            echo "Failed to install $package"

            # Try direct clone and build as fallback for troublesome packages
            echo "Attempting fallback installation method..."
            PKGDIR=$(mktemp -d)
            git clone "https://github.com/$package" "$PKGDIR" 2>/dev/null
            if [ $? -eq 0 ]; then
                # shellcheck disable=SC2164
                cd "$PKGDIR"
                # Remove @version from package path if present
                # shellcheck disable=SC2034
                # shellcheck disable=SC2001
                PKGDIR_NAME=$(echo "$package" | sed 's/@.*//')
                go build -o "$GOPATH/bin/$package_name" ./...
                if [ $? -eq 0 ]; then
                    echo "Successfully built and installed $package_name via direct compilation"
                    chmod +x "$GOPATH/bin/$package_name"
                else
                    echo "Failed to build $package_name via direct compilation"
                fi
                # shellcheck disable=SC2164
                # shellcheck disable=SC2103
                cd - > /dev/null
            else
                echo "Failed to clone repository for $package"
            fi
            rm -rf "$PKGDIR"
        fi
    done
}

# Install npm packages
install_npm_packages() {
    echo "Installing npm packages..."

    # Check if npm is installed
    if ! command -v npm &> /dev/null; then
        echo "npm is not installed. Installing Node.js and npm first..."

        if [ "$PKG_MANAGER" == "brew" ]; then
            brew install node
        elif [ "$PKG_MANAGER" == "apt" ]; then
            sudo apt-get install -y nodejs npm
        elif [ "$PKG_MANAGER" == "dnf" ] || [ "$PKG_MANAGER" == "yum" ]; then
            sudo $PKG_MANAGER install -y nodejs npm
        elif [ "$PKG_MANAGER" == "pacman" ]; then
            sudo pacman -S --noconfirm nodejs npm
        fi

        # Check if npm installation was successful
        if ! command -v npm &> /dev/null; then
            echo "Failed to install npm. Skipping npm packages."
            return
        fi
    fi

    # Get npm packages from config
    # shellcheck disable=SC2155
    local packages=$(jq -r '.packages[] | select(.type == "npm") | .name' "$CONFIG_FILE")

    # Install each package
    for package in $packages; do
        echo "Installing npm package: $package"
        npm install --user "$package" || npm install -g "$package" || echo "Failed to install $package"
    done
}

# Install pip packages
install_pip_packages() {
    echo "Installing pip packages..."

    # Check if pip is installed
    if ! command -v pip3 &> /dev/null; then
        echo "pip3 is not installed. Installing Python3 and pip3 first..."

        if [ "$PKG_MANAGER" == "brew" ]; then
            brew install python3
        elif [ "$PKG_MANAGER" == "apt" ]; then
            sudo apt-get install -y python3 python3-pip
        elif [ "$PKG_MANAGER" == "dnf" ] || [ "$PKG_MANAGER" == "yum" ]; then
            sudo $PKG_MANAGER install -y python3 python3-pip
        elif [ "$PKG_MANAGER" == "pacman" ]; then
            sudo pacman -S --noconfirm python python-pip
        fi

        # Check if pip installation was successful
        if ! command -v pip3 &> /dev/null; then
            echo "Failed to install pip3. Skipping pip packages."
            return
        fi
    fi

    # Get pip packages from config
    # shellcheck disable=SC2155
    local packages=$(jq -r '.packages[] | select(.type == "pip") | .name' "$CONFIG_FILE")

    # Install each package
    for package in $packages; do
        echo "Installing pip package: $package"
        pip3 install --user "$package" || echo "Failed to install $package"
    done
}

# Install Rust/Cargo packages
install_cargo_packages() {
    echo "Installing Cargo packages..."

    # Check if cargo is installed
    if ! command -v cargo &> /dev/null; then
        echo "cargo is not installed. Installing Rust and Cargo first..."

        if [ "$PKG_MANAGER" == "brew" ]; then
            brew install rust
        elif [ "$PKG_MANAGER" == "apt" ]; then
            sudo apt-get install -y rustc cargo
        elif [ "$PKG_MANAGER" == "dnf" ] || [ "$PKG_MANAGER" == "yum" ]; then
            sudo $PKG_MANAGER install -y rust cargo
        elif [ "$PKG_MANAGER" == "pacman" ]; then
            sudo pacman -S --noconfirm rust
        else
            # Fallback to rustup
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
        fi

        # Check if cargo installation was successful
        if ! command -v cargo &> /dev/null; then
            echo "Failed to install cargo. Skipping cargo packages."
            return
        fi
    fi

    # Get cargo packages from config
    # shellcheck disable=SC2155
    local packages=$(jq -r '.packages[] | select(.type == "cargo") | .name' "$CONFIG_FILE")

    # Install each package
    for package in $packages; do
        echo "Installing cargo package: $package"
        cargo install "$package" || echo "Failed to install $package"
    done
}

#!/bin/bash

# Fix the PATH environment variables in shell config files

# Function to check and fix PATH in a given file
fix_path_in_file() {
    local config_file="$1"

    if [[ -f "$config_file" ]]; then
        echo "Checking and fixing PATH in $config_file..."

        # Remove any incorrect PATH entries
        sed -i.bak '/^\..*\.deno\/env"export GOPATH/d' "$config_file"

        # Check for existing GOPATH, GOBIN declarations
        if ! grep -q "^export GOPATH=" "$config_file"; then
            echo "export GOPATH=\$HOME/go" >> "$config_file"
        fi

        if ! grep -q "^export GOBIN=" "$config_file"; then
            echo "export GOBIN=\$GOPATH/bin" >> "$config_file"
        fi

        # Check for PATH including GOPATH/bin
        if ! grep -q "PATH=.*GOPATH/bin" "$config_file"; then
            echo "export PATH=\$PATH:\$GOPATH/bin" >> "$config_file"
        fi

        echo "Fixed PATH configuration in $config_file"
    fi
}

# Identify which shell configuration files exist
shell_files=()
[[ -f ~/.zshrc ]] && shell_files+=("$HOME/.zshrc")
[[ -f ~/.bashrc ]] && shell_files+=("$HOME/.bashrc")
[[ -f ~/.bash_profile ]] && shell_files+=("$HOME/.bash_profile")
[[ -f ~/.profile ]] && shell_files+=("$HOME/.profile")

# Fix PATH in each existing shell config file
for file in "${shell_files[@]}"; do
    fix_path_in_file "$file"
done

echo "PATH configuration has been fixed in your shell config files."
echo "Please restart your terminal or run 'source ~/.zshrc' (or equivalent) to apply changes."

# Configure environment
configure_environment() {
    echo "Configuring environment..."

    # Detect shell
    local shell_rc=""
    if [[ "$SHELL" == *"zsh"* ]]; then
        shell_rc="$HOME/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        shell_rc="$HOME/.bashrc"
    else
        # Default to .profile which should work for most shells
        shell_rc="$HOME/.profile"
    fi

    echo "Using shell configuration file: $shell_rc"

    # Remove any malformed PATH entries first
    sed -i.bak '/^\..*\.deno\/env"export GOPATH/d' "$shell_rc"

    # Set up Go environment if installed
    if command -v go &> /dev/null; then
        # Add GOPATH and GOBIN to environment if not already there
        if ! grep -q "^export GOPATH=" "$shell_rc"; then
            echo -e "\n# Go environment variables" >> "$shell_rc"
            echo "export GOPATH=\$HOME/go" >> "$shell_rc"
        fi

        if ! grep -q "^export GOBIN=" "$shell_rc"; then
            echo "export GOBIN=\$GOPATH/bin" >> "$shell_rc"
        fi

        if ! grep -q "PATH=.*GOPATH/bin" "$shell_rc"; then
            echo "export PATH=\$PATH:\$GOPATH/bin" >> "$shell_rc"
        fi

        # Create Go directories if they don't exist
        mkdir -p "$HOME/go/bin"
    fi

    # Configure additional environment variables from config
    if jq -e '.environment' "$CONFIG_FILE" &>/dev/null; then
        echo -e "\n# Additional environment variables from config" >> "$shell_rc"
        while read -r key value; do
            echo "Setting environment variable: $key=$value"
            # Check if variable is already set
            if ! grep -q "^export $key=" "$shell_rc"; then
                echo "export $key=$value" >> "$shell_rc"
            fi
        done < <(jq -r '.environment | to_entries[] | "\(.key) \(.value)"' "$CONFIG_FILE")
    fi

    echo "Environment variables have been configured in $shell_rc"
}

# Run post-installation commands from config
run_post_install() {
    echo "Running post-installation commands..."

    if jq -e '.post_install' "$CONFIG_FILE" &>/dev/null; then
        while read -r cmd; do
            echo "Executing: $cmd"
            eval "$cmd" || echo "Failed to execute: $cmd"
        done < <(jq -r '.post_install[]' "$CONFIG_FILE")
    fi
}
# Test installed tools
test_installations() {
    echo "Testing installed tools..."

    # Test system packages
    # shellcheck disable=SC2155
    local system_packages=$(jq -r '.packages[] | select(.type == "system") | .name' "$CONFIG_FILE")
    for package in $system_packages; do
        if command -v "$package" &> /dev/null; then
            echo "✓ System package '$package' is properly installed"
        else
            echo "✗ System package '$package' may not be properly installed or not in PATH"
        fi
    done

    # Test Go packages
    # shellcheck disable=SC2155
    local go_packages=$(jq -r '.packages[] | select(.type == "go") | .name' "$CONFIG_FILE")
    for package in $go_packages; do
        # shellcheck disable=SC2155
        local package_name=$(extract_package_name "$package")
        if command -v "$package_name" &> /dev/null || [ -f "$HOME/go/bin/$package_name" ]; then
            echo "✓ Go package '$package_name' is properly installed"
        else
            echo "✗ Go package '$package_name' may not be properly installed or not in PATH"
        fi
    done

    # Remind user about PATH
    echo ""
    echo "NOTE: If tools are installed but not found, you may need to restart your terminal or run:"
    echo "  source $HOME/.zshrc  # if using zsh"
    echo "  source $HOME/.bashrc # if using bash"
    echo "  source $HOME/.profile # otherwise"
}

# Main execution
main() {
    # Default config file path
    CONFIG_FILE="${1:-./tools_config.json}"

    echo "=== Starting Tools Installation Script ==="
    echo "Using configuration file: $CONFIG_FILE"

    # Parse config file
    parse_config "$CONFIG_FILE"

    # Detect operating system and package manager
    detect_system

    # Setup prerequisites
    setup_prerequisites

    # Install package manager if needed
    install_package_manager

    # Install packages by type
    install_system_packages
    install_go_packages
    install_npm_packages
    install_pip_packages
    install_cargo_packages

    # Configure environment
    configure_environment

    # Run post-installation commands
    run_post_install

    # Test installed tools
    test_installations

    echo "=== Installation Complete ==="
    echo "Please restart your terminal or run 'source ~/.zshrc' or 'source ~/.bashrc' to apply all changes."
}

# Execute main function
main "$@"