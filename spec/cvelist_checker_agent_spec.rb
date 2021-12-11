require 'rails_helper'
require 'huginn_agent/spec_helper'

describe Agents::CvelistCheckerAgent do
  before(:each) do
    @valid_options = Agents::CvelistCheckerAgent.new.default_options
    @checker = Agents::CvelistCheckerAgent.new(:name => "CvelistCheckerAgent", :options => @valid_options)
    @checker.user = users(:bob)
    @checker.save!
  end

  pending "add specs here"
end
