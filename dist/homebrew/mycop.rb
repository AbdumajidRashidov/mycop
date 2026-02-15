class Mycop < Formula
  desc "AI-powered code security scanner"
  homepage "https://github.com/AbdumajidRashidov/mycop"
  version "0.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-aarch64-apple-darwin.tar.gz"
      sha256 "740a3bf9e888d46baa01ccb313a536aa190b0a9f71c793bd44f71f32256592d3"
    else
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-x86_64-apple-darwin.tar.gz"
      sha256 "6d038a0b33d36ce16d75045a81fd5b9e06b7a46c84f22a62e89ee3ad13144808"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "e6c96404dc0e3694c23b2813d3617485d278486e3141f9144c0f16217fe8a1fc"
    else
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "8af24f6ba6c32dc1010dc8fe89558605e54fd6af3aab7d781b6346334a8f501e"
    end
  end

  def install
    bin.install "mycop"
  end

  test do
    assert_match "mycop", shell_output("#{bin}/mycop --version")
  end
end
