#!/usr/bin/env ruby
#
# This script can summarize all options used by module type or lists each module with a specified option name
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'
require 'uri'

sort         = 0
filter       = 'All'
filters      = ['all','exploit','payload','post','nop','encoder','auxiliary']
match        = nil
save         = nil
$verbose     = false

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-f" => [ true, "Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = ALL)."],
  "-x" => [ true, "String or RegEx to try and match against the Option Name"],
  "-o" => [ true, "Save the results to a file"],
  "-v" => [ false, "Verbose"]
)

flags = []

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Option information."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-f"
    unless filters.include?(val.downcase)
      puts "Invalid Filter Supplied: #{val}"
      puts "Please use one of these: #{filters.map{|f|f.capitalize}.join(", ")}"
      exit
    end
    flags << "Module Filter: #{val}"
    filter = val
  when "-v"
    $verbose = true
  when "-x"
    flags << "Regex: #{val}"
    match = Regexp.new(val)
  when "-o"
    flags << "Output to file: Yes"
    save = val
  end
}

puts flags * " | "

def get_ipv4_addr(hostname)
  Rex::Socket::getaddresses(hostname, false)[0]
end

def vprint_debug(msg='')
  print_debug(msg) if $verbose
end

def print_debug(msg='')
  $stderr.puts "[*] #{msg}"
end

def save_results(path, results)
  begin
    File.open(path, 'wb') do |f|
      f.write(results)
    end
    puts "Results saved to: #{path}"
  rescue Exception => e
    puts "Failed to save the file: #{e.message}"
  end
end

# Always disable the database (we never need it just to list module
# information).
framework_opts = { 'DisableDatabase' => true }

# If the user only wants a particular module type, no need to load the others
if filter.downcase != 'all'
  framework_opts[:module_types] = [ filter.downcase ]
end

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(framework_opts)

columns = [ 'Option', 'Count']
if match
  columns = [ 'Option', 'Module']
end

tbl = Rex::Text::Table.new(
  'Header'  => 'Module Options',
  'Indent'  => 2,
  'Columns' => columns
)

column_cache = {}

$framework.modules.each { |name, mod|

  next unless mod
  x = mod.new
  x.options.each do |opt, value|
    next if match and not opt =~ match
    # directly build table for each module
    if match
      new_column = []
      new_column << opt
      new_column << name
      tbl << new_column
      next
    end

    # build summary cache to count modules
    if column_cache[opt]
      column_cache[opt] += 1
    else
      column_cache[opt] = 1
    end
  end
}

column_cache.size

column_cache.each do |option, count|
  new_column = []
  new_column << option
  new_column << count
  tbl << new_column
end

if sort == 1
  tbl.sort_rows(1)
end

puts
puts tbl.to_s
puts

save_results(save, tbl.to_s) if save
