require 'socket'
require 'thread'
require 'resolv'
require 'net/http'
require 'json'
require 'csv'
require 'open3'

# Function to retrieve public IP (whoami)
def whoami
  uri = URI('https://api.ipify.org?format=text')
  public_ip = Net::HTTP.get(uri)
  puts "Your public IP is: #{public_ip}"
end

# Function to perform WHOIS lookup
def whois(ip)
  puts "\nPerforming WHOIS lookup for #{ip}..."
  begin
    output, _ = Open3.capture2("whois #{ip}")
    puts output
    output
  rescue
    puts "Error: WHOIS lookup failed. Ensure 'whois' is installed on your system."
    nil
  end
end

# Banner Grabbing Function
def banner_grab(ip, port)
  begin
    socket = Socket.tcp(ip, port, connect_timeout: 2)
    socket.puts "HEAD / HTTP/1.0\r\n\r\n"
    banner = socket.read(1024)
    socket.close
    banner
  rescue
    "No banner detected"
  end
end

# Service Detection
def detect_service(port)
  common_services = {
    21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
    53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 443 => 'HTTPS'
  }
  common_services[port] || "Unknown Service"
end

# Port Scanning Function
def scan_ports(ip, start_port, end_port, timeout, thread_count)
  puts "\nStarting scan on #{ip} from port #{start_port} to #{end_port}..."
  
  open_ports = []
  lock = Mutex.new
  queue = Queue.new
  (start_port..end_port).each { |port| queue << port }

  threads = Array.new(thread_count) do
    Thread.new do
      while !queue.empty?
        port = queue.pop(true) rescue nil
        next unless port
        begin
          socket = Socket.tcp(ip, port, connect_timeout: timeout)
          lock.synchronize do
            service = detect_service(port)
            banner = banner_grab(ip, port)
            open_ports << { port: port, service: service, banner: banner }
            puts "Port #{port} is OPEN (Service: #{service})"
            puts "Banner: #{banner}" unless banner.strip.empty?
          end
          socket.close
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ETIMEDOUT
          # Skip closed or unreachable ports
        end
      end
    end
  end
  threads.each(&:join)

  puts "\nScan Complete!"
  if open_ports.empty?
    puts "No open ports found."
  else
    open_ports.each do |entry|
      puts "Port #{entry[:port]}: #{entry[:service]} | Banner: #{entry[:banner]}"
    end
  end
  open_ports
end

# Save Results to File
def save_results(data, format, filename)
  case format
  when 'txt'
    File.open("#{filename}.txt", 'w') do |file|
      data.each do |entry|
        file.puts "Port #{entry[:port]}: #{entry[:service]} | Banner: #{entry[:banner]}"
      end
    end
  when 'json'
    File.open("#{filename}.json", 'w') do |file|
      file.write(JSON.pretty_generate(data))
    end
  when 'csv'
    CSV.open("#{filename}.csv", 'w') do |csv|
      csv << %w[Port Service Banner]
      data.each do |entry|
        csv << [entry[:port], entry[:service], entry[:banner]]
      end
    end
  else
    puts "Unsupported file format."
  end
  puts "Results saved to #{filename}.#{format}"
end

# Input Validation
def valid_ip?(ip)
  ip.match?(/\A(?:\d{1,3}\.){3}\d{1,3}\z/) && ip.split('.').map(&:to_i).all? { |octet| octet.between?(0, 255) }
end

# Menu
def menu
  puts "\n--- Cybersecurity Scanner Tool ---"
  puts "1. Perform WHOAMI"
  puts "2. Perform WHOIS Lookup"
  puts "3. Scan Ports"
  puts "4. Save Scan Results"
  puts "5. Exit"
  print "Enter your choice: "
  gets.to_i
end

# Main Program
scan_results = []
loop do
  case menu
  when 1
    whoami
  when 2
    print "Enter target IP address: "
    ip = gets.chomp
    unless valid_ip?(ip)
      puts "Invalid IP address."
      next
    end
    whois(ip)
  when 3
    print "Enter target IP address: "
    ip = gets.chomp
    unless valid_ip?(ip)
      puts "Invalid IP address."
      next
    end
    print "Enter starting port: "
    start_port = gets.to_i
    print "Enter ending port: "
    end_port = gets.to_i
    print "Enter timeout (seconds): "
    timeout = gets.to_i
    print "Enter number of threads: "
    thread_count = gets.to_i
    scan_results = scan_ports(ip, start_port, end_port, timeout, thread_count)
  when 4
    if scan_results.empty?
      puts "No scan results available to save."
      next
    end
    print "Enter file format (txt/json/csv): "
    format = gets.chomp
    print "Enter filename (without extension): "
    filename = gets.chomp
    save_results(scan_results, format, filename)
  when 5
    puts "Exiting... Goodbye!"
    break
  else
    puts "Invalid choice. Please try again."
  end
end
