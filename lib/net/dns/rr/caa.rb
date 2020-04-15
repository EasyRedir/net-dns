# frozen_string_literal: true

module Net # :nodoc:
  module DNS
    class RR
      #------------------------------------------------------------
      # RR type CAA
      #------------------------------------------------------------
      class CAA < RR
        attr_reader :flags, :tag, :rr_value

        # Gets the standardized value for this record,
        # represented by the value of <tt>flags</tt>, <tt>tag</tt> and <tt>rr_value</tt>.
        #
        # Returns a String.
        def value
          "#{@flags} #{@tag} #{@rr_value}"
        end

        private

        def build_pack
          str = []
          str << [@flags].pack("C")
          str << [@tag.length].pack("C")
          [@tag, @rr_value].each do |attr|
            str << [attr.length, attr].pack("Ca*")
          end
          @caa_pack = str.join
          @rdlength = @caa_pack.size
        end

        def get_data
          @caa_pack
        end

        def subclass_new_from_hash(options)
          if options.key?(:flags) && options.key?(:tag) && options.key?(:value)
            @flags = options[:flags].to_i
            @tag = options[:tag]
            @rr_value = options[:value]
          else
            raise ArgumentError, ":flags, :tag and :value fields are mandatory"
          end
        end

        def subclass_new_from_string(str)
          @flags, @tag, @rr_value = check_caa(str)
        end

        def subclass_new_from_binary(data, offset)
          off_end = offset + @rdlength
          @flags = data.unpack("@#{offset} C")[0]
          offset += 1
          tag_length = data.unpack("@#{offset} C")[0].ord
          offset += 1
          @tag = data[offset..offset + tag_length - 1]
          offset += tag_length
          @rr_value = "\"#{data[offset..off_end - 1]}\""

          off_end
        end

        def get_inspect
          value
        end

        def check_caa(input)
          # TODO: This method does not currently work because the supplied input is truncated and does not contain the
          # flags attribute.
          str = input.to_s
          if (match = str.strip.match(/^(\d):? (iodef|issue|issuewild):? (".+"):?$/))
            match.captures # returns [flags, tag, rr_value]
          else
            raise ArgumentError, "Invalid CAA section `#{str}'"
          end
        end

        def set_type
          @type = Net::DNS::RR::Types.new("caa")
        end
      end
    end
  end
end
