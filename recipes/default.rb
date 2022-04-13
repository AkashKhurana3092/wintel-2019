#
# Cookbook:: wintel-2019
# Recipe:: default
#
# Copyright:: 2022, The Authors, All Rights Reserved.

include_recipe 'wintel-2019::user'
include_recipe 'wintel-2019::user_rights'
include_recipe 'wintel-2019::security'
include_recipe 'wintel-2019::computer'
include_recipe 'wintel-2019::windows_computer'
