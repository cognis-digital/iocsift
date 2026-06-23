#!/usr/bin/env ruby
# frozen_string_literal: true
# iocsift — extract & defang indicators of compromise (Ruby)
# Part of the Cognis Neural Suite. Single-purpose, JSON-out, CI-tested.
#
# Pulls IPv4s, domains, URLs, emails, and MD5/SHA1/SHA256 hashes out of any
# text (threat reports, logs, emails) and emits a deduped, DEFANGED JSON set
# so the output is safe to paste into tickets/chat.
#
# Usage:
#   iocsift report.txt
#   cat alert.eml | iocsift -
# Options:
#   --no-defang   keep indicators live (do not insert [.] / hxxp)
require 'json'
require 'set'
require 'uri'

defang = true
files = []
ARGV.each do |a|
  case a
  when '--no-defang' then defang = false
  when '-h', '--help'
    warn 'usage: iocsift [--no-defang] FILE|-'
    exit 0
  else files << a
  end
end

text = +''
if files.empty?
  text << $stdin.read
else
  files.each { |f| text << (f == '-' ? $stdin.read : File.read(f)) }
end

PATTERNS = {
  'ipv4'   => /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/,
  'url'    => %r{\bhttps?://[^\s"'<>)\]]+}i,
  'email'  => /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  'sha256' => /\b[a-f0-9]{64}\b/i,
  'sha1'   => /\b[a-f0-9]{40}\b/i,
  'md5'    => /\b[a-f0-9]{32}\b/i,
  'domain' => /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i
}.freeze

# extract longest-token-first so a sha256 isn't also captured as md5/sha1
results = {}
PATTERNS.each { |k, _| results[k] = Set.new }
%w[sha256 sha1 md5 url email ipv4 domain].each do |kind|
  text.scan(PATTERNS[kind]) { |m| results[kind] << (m.is_a?(Array) ? m.first : m) }
end

# a domain that is actually the tail of a captured email/url is noise — drop bare
# domains that appear inside any captured url/email host.
hosts_seen = Set.new
results['url'].each   { |u| hosts_seen << ::URI.parse(u).host rescue nil }
results['email'].each { |e| hosts_seen << e.split('@', 2).last }
results['domain'].reject! { |d| hosts_seen.include?(d) }

def defang_one(kind, v)
  case kind
  when 'url'    then v.sub(%r{^http}i, 'hxxp').gsub('.', '[.]')
  when 'ipv4', 'domain' then v.gsub('.', '[.]')
  when 'email'  then v.sub('@', '[at]').gsub('.', '[.]')
  else v
  end
end

out = { 'tool' => 'iocsift', 'defanged' => defang, 'indicators' => {} }
total = 0
results.each do |kind, set|
  next if set.empty?

  vals = set.to_a.sort
  total += vals.size
  out['indicators'][kind] = defang ? vals.map { |v| defang_one(kind, v) } : vals
end
out['count'] = total

puts JSON.pretty_generate(out)
exit(total.positive? ? 2 : 0)
