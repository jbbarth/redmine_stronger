Deface::Override.new :virtual_path  => 'users/index',
                     :name          => 'add-lock-info-beside-locked-users',
                     :insert_top    => 'td.username',
                     :text          => %(<% if user.locked? && user.try(:lock_comment).present? %>
                                           <div style="float:right;">
                                             <%= content_tag(:span, "",
                                                             :class => "icon icon-help",
                                                             :title => user.lock_comment) %>
                                           </div>
                                         <% end %>)
